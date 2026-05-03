/*
 * cpp_bench.cpp
 *
 * Pure-C++ fizz+folly echo benchmark for tls_bench_ablation. The Tokio
 * runtime and cxx bridge present in the regular fizz_rs binding are absent
 * from this code path; only the Rust call into `run_fizz_cpp_bench` and its
 * return cross the FFI.
 *
 * Threading model intentionally mirrors fizz_rs's binding: one
 * `folly::EventBase` thread per connection on each side (plus one small
 * accept evb on the server). This makes `fizz` (Rust binding) vs.
 * `fizz_cpp` (this binary) an apples-to-apples binding-overhead measurement
 * at every value of `--pairs` — both sides spend the same number of OS
 * threads on crypto / I/O, so the only difference is what sits between the
 * application loop and the fizz state machine.
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
#include <folly/io/async/DelayedDestruction.h>
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
#include <optional>
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

// Session lifecycle: callbacks (read*, write*, handshake*) all fire on the
// per-conn evb thread, so plain bools / counters are safe — no atomic needed.
// We track reads_remaining_ and writes_in_flight_ separately and only stop
// the session once both reach zero (or an error has set us into a stopped
// state AND no writes are pending).
//
// Lifetime is managed via folly::DelayedDestruction — `destroy()` defers
// actual deletion until every callback currently on the stack has unwound
// (each callback opens with a DestructorGuard). This is the canonical folly
// pattern for an object whose own callbacks may fire after a destroy request,
// and it prevents the use-after-free that surfaced when a queued
// `writeSuccess` ran on a session that had already been deleted via a
// runInLoop on the same evb.
class EchoServerSession final
    : public folly::DelayedDestruction,
      public fizz::server::AsyncFizzServer::HandshakeCallback,
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
          reads_remaining_(rounds),
          done_(std::move(done)) {}

    void start() { server_->accept(this); }

    // HandshakeCallback
    void fizzHandshakeSuccess(fizz::server::AsyncFizzServer*) noexcept override {
        DestructorGuard dg(this);
        server_->setReadCB(this);
        if (reads_remaining_ == 0) {
            stopped_ = true;
            maybeFinish();
        }
    }
    void fizzHandshakeError(
        fizz::server::AsyncFizzServer*,
        folly::exception_wrapper ex) noexcept override {
        DestructorGuard dg(this);
        setError("server handshake: " + ex.what().toStdString());
    }
    void fizzHandshakeAttemptFallback(
        fizz::server::AttemptVersionFallback) noexcept override {
        DestructorGuard dg(this);
        setError("server handshake: fallback requested");
    }

    // ReadCallback
    void getReadBuffer(void** buf, size_t* len) override {
        auto p = readQueue_.preallocate(batchSize_, batchSize_ * 2);
        *buf = p.first;
        *len = p.second;
    }
    void readDataAvailable(size_t len) noexcept override {
        DestructorGuard dg(this);
        readQueue_.postallocate(len);
        while (readQueue_.chainLength() >= batchSize_ && reads_remaining_ > 0) {
            auto data = readQueue_.split(batchSize_);
            ++writes_in_flight_;
            --reads_remaining_;
            server_->writeChain(this, std::move(data));
        }
        if (reads_remaining_ == 0 && !stopped_) {
            stopped_ = true;
            maybeFinish();
        }
    }
    void readEOF() noexcept override {
        DestructorGuard dg(this);
        if (reads_remaining_ > 0) {
            setError("server: peer closed mid-stream");
        } else if (!stopped_) {
            stopped_ = true;
            maybeFinish();
        }
    }
    void readErr(const folly::AsyncSocketException& ex) noexcept override {
        DestructorGuard dg(this);
        setError(std::string("server read: ") + ex.what());
    }

    // WriteCallback
    void writeSuccess() noexcept override {
        DestructorGuard dg(this);
        --writes_in_flight_;
        maybeFinish();
    }
    void writeErr(size_t, const folly::AsyncSocketException& ex) noexcept override {
        DestructorGuard dg(this);
        --writes_in_flight_;
        setError(std::string("server write: ") + ex.what());
    }

protected:
    // DelayedDestruction requires destructor to be non-public; clients call
    // destroy() (here, indirectly via maybeFinish).
    ~EchoServerSession() override = default;

private:
    void setError(std::string msg) {
        if (!error_msg_) error_msg_ = std::move(msg);
        stopped_ = true;
        maybeFinish();
    }
    void maybeFinish() {
        if (finished_) return;
        if (!stopped_) return;
        if (writes_in_flight_ > 0) return;
        finished_ = true;
        if (server_) {
            server_->setReadCB(nullptr);
            if (server_->good()) server_->close();
        }
        if (error_msg_) {
            done_.setException(std::runtime_error(*error_msg_));
        } else {
            done_.setValue();
        }
        // DelayedDestruction: actual delete happens after every active
        // DestructorGuard on this object goes out of scope.
        destroy();
    }

    fizz::server::AsyncFizzServer::UniquePtr server_;
    size_t batchSize_;
    size_t reads_remaining_;
    size_t writes_in_flight_{0};
    bool stopped_{false};
    bool finished_{false};
    std::optional<std::string> error_msg_;
    folly::Promise<folly::Unit> done_;
    folly::IOBufQueue readQueue_{folly::IOBufQueue::cacheChainLength()};
};

// ---------------------------------------------------------------------------
// Client-side session: handshake (verify peer DC), then write-then-read loop.
// ---------------------------------------------------------------------------

class EchoClientSession final
    : public folly::DelayedDestruction,
      public fizz::client::AsyncFizzClient::HandshakeCallback,
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
          reads_remaining_(rounds),
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
        DestructorGuard dg(this);
        try {
            const auto& state = client->getState();
            auto peerCert = state.serverCert();
            const auto* peerDC = dynamic_cast<const fizz::extensions::PeerDelegatedCredential*>(
                peerCert.get());
            if (!peerDC) {
                setError("server did not present a delegated credential");
                return;
            }
            std::string err = verify_peer_dc(*ctx_, *peerDC);
            if (!err.empty()) {
                client->closeNow();
                setError(err);
                return;
            }
            client_->setReadCB(this);
            if (reads_remaining_ == 0) {
                stopped_ = true;
                maybeFinish();
                return;
            }
            sendOne();
        } catch (const std::exception& e) {
            setError(std::string("client verify: ") + e.what());
        }
    }
    void fizzHandshakeError(
        fizz::client::AsyncFizzClient*,
        folly::exception_wrapper ex) noexcept override {
        DestructorGuard dg(this);
        setError("client handshake: " + ex.what().toStdString());
    }

    // ReadCallback
    void getReadBuffer(void** buf, size_t* len) override {
        auto p = readQueue_.preallocate(batchSize_, batchSize_ * 2);
        *buf = p.first;
        *len = p.second;
    }
    void readDataAvailable(size_t len) noexcept override {
        DestructorGuard dg(this);
        readQueue_.postallocate(len);
        while (readQueue_.chainLength() >= batchSize_ && reads_remaining_ > 0) {
            readQueue_.split(batchSize_);  // discard echoed bytes
            --reads_remaining_;
            if (reads_remaining_ == 0) {
                stopped_ = true;
                break;
            }
            sendOne();
        }
        if (stopped_) maybeFinish();
    }
    void readEOF() noexcept override {
        DestructorGuard dg(this);
        if (reads_remaining_ > 0) {
            setError("client: peer closed mid-stream");
        } else if (!stopped_) {
            stopped_ = true;
            maybeFinish();
        }
    }
    void readErr(const folly::AsyncSocketException& ex) noexcept override {
        DestructorGuard dg(this);
        setError(std::string("client read: ") + ex.what());
    }

    // WriteCallback
    void writeSuccess() noexcept override {
        DestructorGuard dg(this);
        --writes_in_flight_;
        maybeFinish();
    }
    void writeErr(size_t, const folly::AsyncSocketException& ex) noexcept override {
        DestructorGuard dg(this);
        --writes_in_flight_;
        setError(std::string("client write: ") + ex.what());
    }

protected:
    ~EchoClientSession() override = default;

private:
    void sendOne() {
        auto buf = folly::IOBuf::copyBuffer(sendBuf_.data(), sendBuf_.size());
        ++writes_in_flight_;
        client_->writeChain(this, std::move(buf));
    }
    void setError(std::string msg) {
        if (!error_msg_) error_msg_ = std::move(msg);
        stopped_ = true;
        maybeFinish();
    }
    void maybeFinish() {
        if (finished_) return;
        if (!stopped_) return;
        if (writes_in_flight_ > 0) return;
        finished_ = true;
        if (client_) {
            client_->setReadCB(nullptr);
            if (client_->good()) client_->close();
        }
        if (error_msg_) {
            done_.setException(std::runtime_error(*error_msg_));
        } else {
            done_.setValue();
        }
        // DelayedDestruction: actual delete happens after every active
        // DestructorGuard on this object goes out of scope.
        destroy();
    }

    fizz::client::AsyncFizzClient::UniquePtr client_;
    std::shared_ptr<const fizz::CertificateVerifier> verifier_;
    std::shared_ptr<fizz::extensions::DelegatedCredentialClientExtension> dcExt_;
    const FizzClientContext* ctx_;
    std::string sni_;
    size_t batchSize_;
    size_t reads_remaining_;
    size_t writes_in_flight_{0};
    bool stopped_{false};
    bool finished_{false};
    std::optional<std::string> error_msg_;
    folly::Promise<folly::Unit> done_;
    folly::IOBufQueue readQueue_{folly::IOBufQueue::cacheChainLength()};
    std::vector<uint8_t> sendBuf_;
};

// One EventBase + worker thread, owning a single connection. Mirrors the
// per-conn evb threads spawned inside `server_accept_connection` /
// `client_connect` in the regular fizz_rs binding.
struct PerConnEvb {
    std::unique_ptr<folly::EventBase> evb;
    std::unique_ptr<std::thread> thread;
};

// ---------------------------------------------------------------------------
// Server-side acceptor: each accepted TCP fd gets its OWN evb + thread, and
// the AsyncFizzServer is pinned to that per-conn evb. Listener and accept
// callback live on a separate small "accept evb" so accepting never blocks
// any one connection's I/O thread.
// ---------------------------------------------------------------------------

class BenchAcceptor final : public folly::AsyncServerSocket::AcceptCallback {
public:
    BenchAcceptor(
        std::shared_ptr<fizz::server::FizzServerContext> serverCtx,
        size_t batchSize,
        size_t rounds,
        size_t expectedConns,
        folly::Promise<folly::Unit> allDone,
        std::vector<PerConnEvb>* perConnEvbs,
        std::mutex* perConnMutex)
        : serverCtx_(std::move(serverCtx)),
          batchSize_(batchSize),
          rounds_(rounds),
          expectedConns_(expectedConns),
          allDone_(std::move(allDone)),
          perConnEvbs_(perConnEvbs),
          perConnMutex_(perConnMutex) {}

    void connectionAccepted(
        folly::NetworkSocket fd,
        const folly::SocketAddress&,
        AcceptInfo) noexcept override {
        try {
            auto perConn = std::make_unique<folly::EventBase>();
            auto* evbPtr = perConn.get();
            auto thread = std::make_unique<std::thread>(
                [evbPtr] { evbPtr->loopForever(); });
            {
                std::lock_guard<std::mutex> lock(*perConnMutex_);
                perConnEvbs_->push_back(
                    PerConnEvb{std::move(perConn), std::move(thread)});
            }

            evbPtr->runInEventBaseThread([this, fd, evbPtr] {
                try {
                    auto socket = folly::AsyncSocket::newSocket(evbPtr, fd);
                    auto fizzServer = fizz::server::AsyncFizzServer::UniquePtr(
                        new fizz::server::AsyncFizzServer(
                            std::move(socket), serverCtx_));

                    folly::Promise<folly::Unit> sessionDone;
                    auto sessionFut = sessionDone.getSemiFuture();
                    auto* session = new EchoServerSession(
                        std::move(fizzServer), batchSize_, rounds_,
                        std::move(sessionDone));
                    session->start();

                    std::move(sessionFut).via(evbPtr).thenTry(
                        [this](folly::Try<folly::Unit> t) {
                            if (fired_.load()) return;
                            if (t.hasException()) {
                                if (!fired_.exchange(true)) {
                                    allDone_.setException(t.exception());
                                }
                                return;
                            }
                            if (completed_.fetch_add(1) + 1 == expectedConns_ &&
                                !fired_.exchange(true)) {
                                allDone_.setValue();
                            }
                        });
                } catch (const std::exception& e) {
                    if (!fired_.exchange(true)) {
                        allDone_.setException(std::runtime_error(
                            std::string("server setup: ") + e.what()));
                    }
                }
            });
        } catch (const std::exception& e) {
            if (!fired_.exchange(true)) {
                allDone_.setException(
                    std::runtime_error(std::string("accept: ") + e.what()));
            }
        }
    }

    void acceptError(folly::exception_wrapper ex) noexcept override {
        if (!fired_.exchange(true)) {
            allDone_.setException(
                std::runtime_error("acceptError: " + ex.what().toStdString()));
        }
    }

private:
    std::shared_ptr<fizz::server::FizzServerContext> serverCtx_;
    size_t batchSize_;
    size_t rounds_;
    size_t expectedConns_;
    folly::Promise<folly::Unit> allDone_;
    std::vector<PerConnEvb>* perConnEvbs_;
    std::mutex* perConnMutex_;
    std::atomic<size_t> completed_{0};
    std::atomic<bool> fired_{false};
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

    // Small dedicated evb just for the AsyncServerSocket / accept loop. Per
    // accepted conn we spawn a fresh evb thread (mirrors fizz_rs binding).
    folly::EventBase acceptEvb;
    std::thread acceptThread([&] { acceptEvb.loopForever(); });

    std::vector<PerConnEvb> serverPerConnEvbs;
    serverPerConnEvbs.reserve(pairs);
    std::mutex serverPerConnMutex;

    std::vector<PerConnEvb> clientPerConnEvbs;
    clientPerConnEvbs.reserve(pairs);

    folly::Promise<folly::Unit> serverAllDone;
    auto serverAllFut = serverAllDone.getSemiFuture();

    auto* acceptor = new BenchAcceptor(
        serverCtx, batchSize, rounds, pairs, std::move(serverAllDone),
        &serverPerConnEvbs, &serverPerConnMutex);

    folly::AsyncServerSocket::UniquePtr listener;
    uint16_t port = 0;
    acceptEvb.runInEventBaseThreadAndWait([&] {
        listener = folly::AsyncServerSocket::UniquePtr(
            new folly::AsyncServerSocket(&acceptEvb));
        listener->bind(0);
        listener->listen(static_cast<int>(pairs) + 8);
        listener->addAcceptCallback(acceptor, &acceptEvb);
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

        auto perConn = std::make_unique<folly::EventBase>();
        auto* evbPtr = perConn.get();
        auto thread = std::make_unique<std::thread>(
            [evbPtr] { evbPtr->loopForever(); });
        clientPerConnEvbs.push_back(
            PerConnEvb{std::move(perConn), std::move(thread)});

        evbPtr->runInEventBaseThread([&, tcpFd, evbPtr] {
            try {
                folly::NetworkSocket netSock(tcpFd);
                auto socket = folly::AsyncSocket::newSocket(evbPtr, netSock);
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

                std::move(sessionFut).via(evbPtr).thenTry(
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

    acceptEvb.runInEventBaseThreadAndWait([&] {
        listener->stopAccepting();
        listener.reset();
    });
    delete acceptor;

    acceptEvb.terminateLoopSoon();
    acceptThread.join();

    // Stop every per-conn evb, then join all threads. Done in two passes so
    // teardown isn't serialized one thread at a time.
    for (auto& pc : serverPerConnEvbs) {
        pc.evb->terminateLoopSoon();
    }
    for (auto& pc : clientPerConnEvbs) {
        pc.evb->terminateLoopSoon();
    }
    for (auto& pc : serverPerConnEvbs) {
        pc.thread->join();
    }
    for (auto& pc : clientPerConnEvbs) {
        pc.thread->join();
    }

    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
}
