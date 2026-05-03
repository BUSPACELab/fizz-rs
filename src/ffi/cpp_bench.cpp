/*
 * cpp_bench.cpp
 *
 * Pure-C++ fizz+folly echo benchmark for tls_bench_ablation experiment 2a.
 * The Tokio runtime, cxx bridge, and per-connection evb threads in the regular
 * fizz_rs binding are all absent from this code path; only the Rust call into
 * `run_fizz_cpp_bench` and the call back to Rust on return cross the FFI.
 * Two shared `folly::EventBase` threads (one per side) drive every connection.
 */

#define GLOG_USE_GLOG_EXPORT

#include "ffi/cpp_bench.h"
#include "ffi/server_tls_ffi.h"
#include "ffi/client_tls_ffi.h"

#include <fizz/client/AsyncFizzClient.h>
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialClientExtension.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/PeerDelegatedCredential.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/IOBufQueue.h>
#include <folly/futures/Future.h>
#include <folly/futures/Promise.h>
#include <folly/ssl/OpenSSLCertUtils.h>

#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::shared_ptr<fizz::DefaultCertificateVerifier> create_verifier(
    const std::string& caCertPath) {
    folly::ssl::X509StoreUniquePtr store(X509_STORE_new());
    if (!store ||
        X509_STORE_load_locations(store.get(), caCertPath.c_str(), nullptr) == 0) {
        throw std::runtime_error("cpp_bench: failed to load CA from " + caCertPath);
    }
    return std::make_shared<fizz::DefaultCertificateVerifier>(
        fizz::VerificationContext::Client, std::move(store));
}

// Match fizz_rs's verifyVerificationInfoAgainstPeerDelegatedCredential —
// expects a peer DC and that its fields match what the Rust caller pinned.
// Returns empty string on success, or a short error message.
std::string verify_peer_dc(
    const FizzClientContext& ctx,
    const fizz::extensions::PeerDelegatedCredential& peerDC) {
    const auto& dc = peerDC.getDelegatedCredential();

    auto bytes_to_hex = [](folly::ByteRange r) {
        static const char* lut = "0123456789abcdef";
        std::string out;
        out.resize(r.size() * 2);
        for (size_t i = 0; i < r.size(); ++i) {
            out[2 * i]     = lut[(r[i] >> 4) & 0xF];
            out[2 * i + 1] = lut[r[i] & 0xF];
        }
        return out;
    };

    if (bytes_to_hex(dc.public_key->coalesce()) != ctx.publicKeyDer) {
        return "DC public key does not match VerificationInfo";
    }
    if (dc.valid_time != ctx.validTime) {
        return "DC valid_time does not match VerificationInfo";
    }
    if (static_cast<uint16_t>(dc.expected_verify_scheme) != ctx.expectedVerifyScheme) {
        return "DC verify scheme does not match VerificationInfo";
    }
    folly::ssl::X509UniquePtr leaf = peerDC.getX509();
    auto expTp = fizz::extensions::DelegatedCredentialUtils::getCredentialExpiresTime(leaf, dc);
    auto expSec = std::chrono::duration_cast<std::chrono::seconds>(
        expTp.time_since_epoch()).count();
    if (static_cast<uint64_t>(expSec) != ctx.expiresAt) {
        return "DC expiry does not match VerificationInfo";
    }
    return {};
}

int blocking_tcp_connect(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) throw std::runtime_error("cpp_bench: socket()");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(0x7F000001); // 127.0.0.1
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        throw std::runtime_error("cpp_bench: connect()");
    }
    return fd;
}

// ---------------------------------------------------------------------------
// Server-side session: handshake, then read-then-echo loop until `rounds`
// batches have been written. Self-deletes when finished.
// ---------------------------------------------------------------------------

class EchoServerSession final
    : public fizz::server::AsyncFizzServer::HandshakeCallback,
      public folly::AsyncTransportWrapper::ReadCallback,
      public folly::AsyncTransportWrapper::WriteCallback {
public:
    EchoServerSession(
        fizz::server::AsyncFizzServer::UniquePtr server,
        size_t batchSize,
        size_t rounds,
        folly::Promise<folly::Unit> done)
        : server_(std::move(server)),
          batchSize_(batchSize),
          remaining_(rounds),
          done_(std::move(done)) {}

    void start() { server_->accept(this); }

    // HandshakeCallback
    void fizzHandshakeSuccess(fizz::server::AsyncFizzServer*) noexcept override {
        server_->setReadCB(this);
    }
    void fizzHandshakeError(
        fizz::server::AsyncFizzServer*,
        folly::exception_wrapper ex) noexcept override {
        finishErr("server handshake: " + ex.what().toStdString());
    }
    void fizzHandshakeAttemptFallback(
        fizz::server::AttemptVersionFallback) noexcept override {
        finishErr("server handshake: fallback requested");
    }

    // ReadCallback
    void getReadBuffer(void** buf, size_t* len) override {
        auto p = readQueue_.preallocate(batchSize_, batchSize_ * 2);
        *buf = p.first;
        *len = p.second;
    }
    void readDataAvailable(size_t len) noexcept override {
        readQueue_.postallocate(len);
        while (readQueue_.chainLength() >= batchSize_ && remaining_ > 0) {
            auto data = readQueue_.split(batchSize_);
            server_->writeChain(this, std::move(data));
        }
    }
    void readEOF() noexcept override {
        if (remaining_ > 0) finishErr("server: peer closed mid-stream");
    }
    void readErr(const folly::AsyncSocketException& ex) noexcept override {
        finishErr(std::string("server read: ") + ex.what());
    }

    // WriteCallback
    void writeSuccess() noexcept override {
        if (--remaining_ == 0) {
            server_->setReadCB(nullptr);
            server_->close();
            finishOk();
        }
    }
    void writeErr(size_t, const folly::AsyncSocketException& ex) noexcept override {
        finishErr(std::string("server write: ") + ex.what());
    }

private:
    void finishOk() {
        if (!finished_.exchange(true)) {
            done_.setValue();
            scheduleSelfDelete();
        }
    }
    void finishErr(const std::string& msg) {
        if (!finished_.exchange(true)) {
            done_.setException(std::runtime_error(msg));
            scheduleSelfDelete();
        }
    }
    void scheduleSelfDelete() {
        // Defer to the next loop tick so we don't free ourselves from inside
        // a fizz/folly callback that's still walking our v-table.
        server_->getEventBase()->runInLoop([this] { delete this; });
    }

    fizz::server::AsyncFizzServer::UniquePtr server_;
    size_t batchSize_;
    size_t remaining_;
    folly::Promise<folly::Unit> done_;
    folly::IOBufQueue readQueue_{folly::IOBufQueue::cacheChainLength()};
    std::atomic<bool> finished_{false};
};

// ---------------------------------------------------------------------------
// Client-side session: handshake (verify peer DC), then write-then-read loop.
// ---------------------------------------------------------------------------

class EchoClientSession final
    : public fizz::client::AsyncFizzClient::HandshakeCallback,
      public folly::AsyncTransportWrapper::ReadCallback,
      public folly::AsyncTransportWrapper::WriteCallback {
public:
    EchoClientSession(
        fizz::client::AsyncFizzClient::UniquePtr client,
        std::shared_ptr<const fizz::CertificateVerifier> verifier,
        std::shared_ptr<fizz::extensions::DelegatedCredentialClientExtension> dcExt,
        const FizzClientContext* ctx,
        std::string sni,
        size_t batchSize,
        size_t rounds,
        folly::Promise<folly::Unit> done)
        : client_(std::move(client)),
          verifier_(std::move(verifier)),
          dcExt_(std::move(dcExt)),
          ctx_(ctx),
          sni_(std::move(sni)),
          batchSize_(batchSize),
          remaining_(rounds),
          done_(std::move(done)) {
        sendBuf_.assign(batchSize_, 0x5A);
    }

    void start() {
        folly::Optional<std::string> sniOpt = sni_.empty()
            ? folly::none
            : folly::Optional<std::string>(sni_);
        client_->connect(
            this,
            verifier_,
            sniOpt,
            folly::none,
            folly::none,
            std::chrono::milliseconds(120000));
    }

    // HandshakeCallback
    void fizzHandshakeSuccess(fizz::client::AsyncFizzClient* client) noexcept override {
        try {
            const auto& state = client->getState();
            auto peerCert = state.serverCert();
            const auto* peerDC = dynamic_cast<const fizz::extensions::PeerDelegatedCredential*>(
                peerCert.get());
            if (!peerDC) {
                finishErr("server did not present a delegated credential");
                return;
            }
            std::string err = verify_peer_dc(*ctx_, *peerDC);
            if (!err.empty()) {
                client->closeNow();
                finishErr(err);
                return;
            }
            client_->setReadCB(this);
            sendOne();
        } catch (const std::exception& e) {
            finishErr(std::string("client verify: ") + e.what());
        }
    }
    void fizzHandshakeError(
        fizz::client::AsyncFizzClient*,
        folly::exception_wrapper ex) noexcept override {
        finishErr("client handshake: " + ex.what().toStdString());
    }

    // ReadCallback
    void getReadBuffer(void** buf, size_t* len) override {
        auto p = readQueue_.preallocate(batchSize_, batchSize_ * 2);
        *buf = p.first;
        *len = p.second;
    }
    void readDataAvailable(size_t len) noexcept override {
        readQueue_.postallocate(len);
        while (readQueue_.chainLength() >= batchSize_ && remaining_ > 0) {
            readQueue_.split(batchSize_);  // discard echoed bytes
            if (--remaining_ == 0) {
                client_->setReadCB(nullptr);
                client_->close();
                finishOk();
                return;
            }
            sendOne();
        }
    }
    void readEOF() noexcept override {
        if (remaining_ > 0) finishErr("client: peer closed mid-stream");
    }
    void readErr(const folly::AsyncSocketException& ex) noexcept override {
        finishErr(std::string("client read: ") + ex.what());
    }

    // WriteCallback
    void writeSuccess() noexcept override {
        // Wait for echo via readDataAvailable.
    }
    void writeErr(size_t, const folly::AsyncSocketException& ex) noexcept override {
        finishErr(std::string("client write: ") + ex.what());
    }

private:
    void sendOne() {
        auto buf = folly::IOBuf::copyBuffer(sendBuf_.data(), sendBuf_.size());
        client_->writeChain(this, std::move(buf));
    }
    void finishOk() {
        if (!finished_.exchange(true)) {
            done_.setValue();
            scheduleSelfDelete();
        }
    }
    void finishErr(const std::string& msg) {
        if (!finished_.exchange(true)) {
            done_.setException(std::runtime_error(msg));
            scheduleSelfDelete();
        }
    }
    void scheduleSelfDelete() {
        client_->getEventBase()->runInLoop([this] { delete this; });
    }

    fizz::client::AsyncFizzClient::UniquePtr client_;
    std::shared_ptr<const fizz::CertificateVerifier> verifier_;
    std::shared_ptr<fizz::extensions::DelegatedCredentialClientExtension> dcExt_;
    const FizzClientContext* ctx_;
    std::string sni_;
    size_t batchSize_;
    size_t remaining_;
    folly::Promise<folly::Unit> done_;
    folly::IOBufQueue readQueue_{folly::IOBufQueue::cacheChainLength()};
    std::vector<uint8_t> sendBuf_;
    std::atomic<bool> finished_{false};
};

// ---------------------------------------------------------------------------
// Server-side acceptor: turns each accepted TCP fd into an EchoServerSession.
// ---------------------------------------------------------------------------

class BenchAcceptor final : public folly::AsyncServerSocket::AcceptCallback {
public:
    BenchAcceptor(
        std::shared_ptr<fizz::server::FizzServerContext> serverCtx,
        folly::EventBase* serverEvb,
        size_t batchSize,
        size_t rounds,
        size_t expectedConns,
        folly::Promise<folly::Unit> allDone)
        : serverCtx_(std::move(serverCtx)),
          serverEvb_(serverEvb),
          batchSize_(batchSize),
          rounds_(rounds),
          expectedConns_(expectedConns),
          allDone_(std::move(allDone)) {}

    void connectionAccepted(
        folly::NetworkSocket fd,
        const folly::SocketAddress&,
        AcceptInfo) noexcept override {
        try {
            auto socket = folly::AsyncSocket::newSocket(serverEvb_, fd);
            auto fizzServer = fizz::server::AsyncFizzServer::UniquePtr(
                new fizz::server::AsyncFizzServer(std::move(socket), serverCtx_));

            folly::Promise<folly::Unit> sessionDone;
            auto sessionFut = sessionDone.getSemiFuture();
            auto* session = new EchoServerSession(
                std::move(fizzServer), batchSize_, rounds_, std::move(sessionDone));
            session->start();

            std::move(sessionFut).via(serverEvb_).thenTry(
                [this](folly::Try<folly::Unit> t) {
                    if (fired_) return;
                    if (t.hasException()) {
                        fired_ = true;
                        allDone_.setException(t.exception());
                        return;
                    }
                    if (++completed_ == expectedConns_) {
                        fired_ = true;
                        allDone_.setValue();
                    }
                });
        } catch (const std::exception& e) {
            if (!fired_) {
                fired_ = true;
                allDone_.setException(
                    std::runtime_error(std::string("accept: ") + e.what()));
            }
        }
    }

    void acceptError(folly::exception_wrapper ex) noexcept override {
        if (!fired_) {
            fired_ = true;
            allDone_.setException(
                std::runtime_error("acceptError: " + ex.what().toStdString()));
        }
    }

private:
    std::shared_ptr<fizz::server::FizzServerContext> serverCtx_;
    folly::EventBase* serverEvb_;
    size_t batchSize_;
    size_t rounds_;
    size_t expectedConns_;
    folly::Promise<folly::Unit> allDone_;
    size_t completed_{0};
    bool fired_{false};
};

}  // namespace

// ===========================================================================
// Entry point called from Rust.
// ===========================================================================

uint64_t run_fizz_cpp_bench(
    const FizzServerContext& serverCtxWrapper,
    const FizzClientContext& clientCtxWrapper,
    uint64_t pairs,
    uint64_t batchSize,
    uint64_t rounds) {
    if (pairs == 0 || rounds == 0 || batchSize == 0) {
        return 0;
    }

    auto serverCtx = serverCtxWrapper.ctx;
    auto clientCtx = clientCtxWrapper.ctx;
    auto verifier = create_verifier(clientCtxWrapper.caCertPath);

    folly::EventBase serverEvb;
    folly::EventBase clientEvb;
    std::thread serverThread([&] { serverEvb.loopForever(); });
    std::thread clientThread([&] { clientEvb.loopForever(); });

    folly::Promise<folly::Unit> serverAllDone;
    auto serverAllFut = serverAllDone.getSemiFuture();

    auto* acceptor = new BenchAcceptor(
        serverCtx, &serverEvb, batchSize, rounds, pairs, std::move(serverAllDone));

    folly::AsyncServerSocket::UniquePtr listener;
    uint16_t port = 0;
    serverEvb.runInEventBaseThreadAndWait([&] {
        listener = folly::AsyncServerSocket::UniquePtr(
            new folly::AsyncServerSocket(&serverEvb));
        listener->bind(0);
        listener->listen(static_cast<int>(pairs) + 8);
        listener->addAcceptCallback(acceptor, &serverEvb);
        listener->startAccepting();
        port = listener->getAddress().getPort();
    });

    folly::Promise<folly::Unit> clientAllDone;
    auto clientAllFut = clientAllDone.getSemiFuture();
    std::atomic<size_t> clientCompleted{0};
    std::atomic<bool> clientFired{false};

    auto t0 = std::chrono::steady_clock::now();

    for (uint64_t i = 0; i < pairs; ++i) {
        int tcpFd = blocking_tcp_connect(port);
        clientEvb.runInEventBaseThread([&, tcpFd] {
            try {
                folly::NetworkSocket netSock(tcpFd);
                auto socket = folly::AsyncSocket::newSocket(&clientEvb, netSock);
                auto dcExt = std::make_shared<
                    fizz::extensions::DelegatedCredentialClientExtension>(
                    std::vector<fizz::SignatureScheme>{
                        fizz::SignatureScheme::ecdsa_secp256r1_sha256,
                        fizz::SignatureScheme::ecdsa_secp384r1_sha384,
                        fizz::SignatureScheme::ecdsa_secp521r1_sha512,
                        fizz::SignatureScheme::rsa_pss_sha256,
                    });
                auto fizzClient = fizz::client::AsyncFizzClient::UniquePtr(
                    new fizz::client::AsyncFizzClient(
                        std::move(socket), clientCtx, dcExt));

                folly::Promise<folly::Unit> sessionDone;
                auto sessionFut = sessionDone.getSemiFuture();
                auto* session = new EchoClientSession(
                    std::move(fizzClient), verifier, dcExt,
                    &clientCtxWrapper, "localhost",
                    batchSize, rounds, std::move(sessionDone));
                session->start();

                std::move(sessionFut).via(&clientEvb).thenTry(
                    [&](folly::Try<folly::Unit> t) {
                        if (clientFired.load()) return;
                        if (t.hasException()) {
                            if (!clientFired.exchange(true)) {
                                clientAllDone.setException(t.exception());
                            }
                            return;
                        }
                        if (clientCompleted.fetch_add(1) + 1 == pairs &&
                            !clientFired.exchange(true)) {
                            clientAllDone.setValue();
                        }
                    });
            } catch (const std::exception& e) {
                if (!clientFired.exchange(true)) {
                    clientAllDone.setException(std::runtime_error(
                        std::string("client setup: ") + e.what()));
                }
            }
        });
    }

    // Block until both sides finish (or one errors).
    std::move(serverAllFut).get();
    std::move(clientAllFut).get();

    auto t1 = std::chrono::steady_clock::now();

    serverEvb.runInEventBaseThreadAndWait([&] {
        listener->stopAccepting();
        listener.reset();
    });
    delete acceptor;

    serverEvb.terminateLoopSoon();
    clientEvb.terminateLoopSoon();
    serverThread.join();
    clientThread.join();

    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
}
