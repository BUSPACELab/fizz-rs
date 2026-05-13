/*
 * server_tls_ffi.cpp
 *
 * Implementation of server-side TLS FFI functions with delegated credentials.
 */

#define GLOG_USE_GLOG_EXPORT

#include "ffi/server_tls_ffi.h"
#include "fizz_rs/src/bridge.rs.h"
#include <fizz/server/AsyncFizzServer.h>
#include <fizz/server/DefaultCertManager.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/server/AeadTicketCipher.h>
#include <fizz/backend/openssl/certificate/OpenSSLSelfCertImpl.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialFactory.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/Serialization.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/IOBufQueue.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdexcept>
#include <chrono>
#include <iostream>
#include <thread>
#include <array>
#include <iterator>
#include <variant>

//TODO(douk): Maybe session resumption with ticket cipher
static std::shared_ptr<fizz::server::TicketCipher> createTicketCipher() {
    return nullptr;
}

//TODO: Shared EVB (Lazy start at first connection establishment could cause handshake timeout issue.)
// const std::shared_ptr<folly::EventBase> SHARED_EVENT_BASE = std::make_shared<folly::EventBase>();
//
// void start_shared_evb() {
//
// }

// ============================================================================
// Server Context Creation
// ============================================================================

std::unique_ptr<FizzServerContext> new_server_tls_context(
    const CertificatePublic& parent_cert,
    const ServiceCredential& delegated_cred) {
    try {
        auto context = std::make_unique<FizzServerContext>();

        // Create Fizz server context
        context->ctx = std::make_shared<fizz::server::FizzServerContext>();

        // Load delegated credential from PEM
        // CRITICAL: Parent cert MUST come BEFORE delegated credential PEM
        // This matches Fizz's loadDCFromPEM() expectations and the C++ reference implementation
        std::string combinedPEM = std::string(parent_cert.cert_pem) +
                                  std::string(delegated_cred.credential_pem);

        auto dcCert = fizz::extensions::loadDCFromPEM(
            combinedPEM,
            fizz::extensions::DelegatedCredentialMode::Server);

        if (!dcCert) {
            throw std::runtime_error("Failed to load delegated credential from PEM");
        }

        // Create delegated credential cert manager
        context->certManager = std::make_unique<
            fizz::extensions::DelegatedCredentialCertManager>();

        context->certManager->addDelegatedCredentialAndSetDefault(
            std::shared_ptr<fizz::extensions::SelfDelegatedCredential>(
                std::move(dcCert)));

        // Set cert manager in context
        context->ctx->setCertManager(std::move(context->certManager));

        // Create and set ticket cipher for session resumption
        context->ticketCipher = createTicketCipher();
        context->ctx->setTicketCipher(context->ticketCipher);

        // Configure supported versions
        context->ctx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});

        // Configure supported ciphers
        context->ctx->setSupportedCiphers({{
            fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
            fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
            fizz::CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        }});

        // Configure supported signature schemes
        context->ctx->setSupportedSigSchemes({{
            fizz::SignatureScheme::ecdsa_secp256r1_sha256,
            fizz::SignatureScheme::ecdsa_secp384r1_sha384,
            fizz::SignatureScheme::ecdsa_secp521r1_sha512,
            fizz::SignatureScheme::rsa_pss_sha256
        }});

        // Configure supported groups
        context->ctx->setSupportedGroups({{
            fizz::NamedGroup::secp256r1,
            fizz::NamedGroup::secp384r1,
            fizz::NamedGroup::secp521r1,
            fizz::NamedGroup::x25519
        }});

        // Initialize ALPN protocols list (empty for now, can be set later)
        context->alpnProtocols = {};

        return context;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create server TLS context: " + std::string(e.what()));
    }
}

std::unique_ptr<FizzServerContext> new_server_tls_context_no_dc(
    const CertificateData& parent_cert) {
    try {
        auto context = std::make_unique<FizzServerContext>();

        context->ctx = std::make_shared<fizz::server::FizzServerContext>();

        // Parse parent certificate and private key from PEM.
        std::string certPemStr(parent_cert.cert_pem);
        folly::ssl::BioUniquePtr certBio(
            BIO_new_mem_buf(certPemStr.data(), certPemStr.size()));
        X509* certRaw = PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr);
        if (!certRaw) {
            throw std::runtime_error("Failed to parse parent certificate PEM");
        }
        folly::ssl::X509UniquePtr certPtr(certRaw);

        std::string keyPemStr(parent_cert.key_pem);
        folly::ssl::BioUniquePtr keyBio(
            BIO_new_mem_buf(keyPemStr.data(), keyPemStr.size()));
        EVP_PKEY* keyRaw = PEM_read_bio_PrivateKey(
            keyBio.get(), nullptr, nullptr, nullptr);
        if (!keyRaw) {
            throw std::runtime_error("Failed to parse parent private key PEM");
        }
        folly::ssl::EvpPkeyUniquePtr keyPtr(keyRaw);

        std::vector<folly::ssl::X509UniquePtr> certs;
        certs.push_back(std::move(certPtr));
        auto selfCert = std::make_shared<
            fizz::openssl::OpenSSLSelfCertImpl<fizz::openssl::KeyType::P256>>(
            std::move(keyPtr), std::move(certs));

        auto certManager = std::make_unique<fizz::server::DefaultCertManager>();
        certManager->addCertAndSetDefault(std::move(selfCert));
        context->ctx->setCertManager(std::move(certManager));

        context->ticketCipher = createTicketCipher();
        context->ctx->setTicketCipher(context->ticketCipher);

        context->ctx->setSupportedVersions({fizz::ProtocolVersion::tls_1_3});
        context->ctx->setSupportedCiphers({{
            fizz::CipherSuite::TLS_AES_128_GCM_SHA256,
            fizz::CipherSuite::TLS_AES_256_GCM_SHA384,
            fizz::CipherSuite::TLS_CHACHA20_POLY1305_SHA256
        }});
        context->ctx->setSupportedSigSchemes({{
            fizz::SignatureScheme::ecdsa_secp256r1_sha256,
            fizz::SignatureScheme::ecdsa_secp384r1_sha384,
            fizz::SignatureScheme::ecdsa_secp521r1_sha512,
            fizz::SignatureScheme::rsa_pss_sha256
        }});
        context->ctx->setSupportedGroups({{
            fizz::NamedGroup::secp256r1,
            fizz::NamedGroup::secp384r1,
            fizz::NamedGroup::secp521r1,
            fizz::NamedGroup::x25519
        }});

        context->alpnProtocols = {};

        return context;
    } catch (const std::exception& e) {
        throw std::runtime_error(
            "Failed to create non-DC server TLS context: " + std::string(e.what()));
    }
}

void server_context_set_alpn_protocols(
    FizzServerContext& ctx,
    rust::Vec<rust::String> protocols) {
    try {
        ctx.alpnProtocols.clear();
        for (const auto& proto : protocols) {
            ctx.alpnProtocols.push_back(std::string(proto));
        }

        if (!ctx.alpnProtocols.empty()) {
            ctx.ctx->setSupportedAlpns(ctx.alpnProtocols);
        }
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to set ALPN protocols: " + std::string(e.what()));
    }
}

// ============================================================================
// Server Connection Management
// ============================================================================

// Destructor for FizzServerConnection - ensures EventBase thread is cleaned up
FizzServerConnection::~FizzServerConnection() {
    try {
        // Stop EventBase thread if it's running
        if (evb_thread && evb_thread->joinable()) {
            if (evb) {
                evb->terminateLoopSoon();
            }
            evb_thread->join();
        }

    } catch (...) {
        // Swallow exceptions in destructor to avoid std::terminate
    }
}

void FizzServerConnection::getReadBuffer(void** bufReturn, size_t* lenReturn) {
    // Held until the matched readDataAvailable / readEOF / readErr fires.
    read_mutex.lock();
    pending_read = true;
    auto result = readBufQueue_.preallocate(40960, 65536);
    *bufReturn = result.first;
    *lenReturn = result.second;
}

void FizzServerConnection::readDataAvailable(size_t len) noexcept {
    readBufQueue_.postallocate(len);
    bytesRead += len;
    pending_read = false;
    read_mutex.unlock();
    if (read_waker) {
        wake_read_waker(**read_waker);
    }
}

void FizzServerConnection::readEOF() noexcept {
    readEof.store(true, std::memory_order_release);
    if (pending_read) {
        pending_read = false;
        read_mutex.unlock();
    }
    auto* transport_ = static_cast<fizz::server::AsyncFizzServer*>(transport);
    transport_->closeNow();
    if (read_waker) {
        wake_read_waker(**read_waker);
    }
}

void FizzServerConnection::readErr(const folly::AsyncSocketException& ex) noexcept {
    errorMessage = ex.what();
    std::cerr << "Got error" << errorMessage << std::endl;
    if (pending_read) {
        pending_read = false;
        read_mutex.unlock();
    }
    auto* transport_ = static_cast<fizz::server::AsyncFizzServer*>(transport);
    transport_->closeNow();
}

std::unique_ptr<FizzServerConnection> server_accept_connection(
    const FizzServerContext& ctx,
    int32_t fd) {
    try {
        auto conn = std::make_unique<FizzServerConnection>();

        // Create EventBase for this connection
        conn->evb = std::make_unique<folly::EventBase>();
        conn->fd = fd;
        conn->handshakeComplete = false;
        conn->errorMessage.clear();
        conn->bytesRead = 0;

        // Create AsyncSocket from file descriptor
        // Note: AsyncSocket takes ownership of the FD
        folly::NetworkSocket networkSocket(fd);
        auto socket = folly::AsyncSocket::newSocket(conn->evb.get(), networkSocket);

        // Create AsyncFizzServer with the socket and context
        auto fizzServer = fizz::server::AsyncFizzServer::UniquePtr(
            new fizz::server::AsyncFizzServer(
                std::move(socket),
                ctx.ctx
            )
        );

        // Store transport pointer (cast to void* to avoid header dependency)
        conn->transport = fizzServer.release();

        // Start EventBase thread to process async operations
        // This thread will run the event loop until the connection is closed
        auto evb_ptr = conn->evb.get();
        conn->evb_thread = std::make_unique<std::thread>([evb_ptr]() {
            // Run the EventBase loop forever (until terminateLoopSoon() is called)
            evb_ptr->loopForever();
        });

        return conn;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to accept connection: " + std::string(e.what()));
    }
}

void server_connection_handshake(FizzServerConnection& conn) {
    try {
        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }
        


        auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);

        // Handshake callback implementation
        class ServerHandshakeCallback : public fizz::server::AsyncFizzServer::HandshakeCallback {
            bool& complete_;
            std::string& error_;
            FizzServerConnection* conn_;

        public:
            ServerHandshakeCallback(bool& complete, std::string& error, FizzServerConnection* conn)
                : complete_(complete), error_(error), conn_(conn){}

            void fizzHandshakeSuccess(fizz::server::AsyncFizzServer* server) noexcept override {
                complete_ = true;
                server->setReadCB(conn_);
            }

            void fizzHandshakeError(
                fizz::server::AsyncFizzServer*,
                folly::exception_wrapper ex) noexcept override {
                std::cout << "Getting an error during handshake" << std::endl;
                error_ = ex.what().toStdString();
            }

            void fizzHandshakeAttemptFallback(fizz::server::AttemptVersionFallback fallback) noexcept override {
                // We don't support version fallback - treat as error
                error_ = "Version fallback attempted";
                complete_ = true;
            }
        };


        auto* callback = new ServerHandshakeCallback(
            conn.handshakeComplete,
            conn.errorMessage,
            &conn
        );

        conn.evb->runInEventBaseThreadAndWait([&]() {
          transport->accept(callback);
        });

        // Wait for handshake to complete (processed by EventBase thread).
        // Under many concurrent accepts, handshakes may queue; keep this generous.
        auto startTime = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(120);

        while (!conn.handshakeComplete && conn.errorMessage.empty()) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                throw std::runtime_error("Handshake timed out after 120 seconds");
            }

            // Just sleep - EventBase thread will process the handshake
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // Check for errors
        if (!conn.errorMessage.empty()) {
            throw std::runtime_error("Handshake failed: " + conn.errorMessage);
        }

        if (!conn.handshakeComplete) {
            throw std::runtime_error("Handshake did not complete");
        }

    } catch (const std::exception& e) {
        conn.handshakeComplete = false;
        throw std::runtime_error("Server handshake failed: " + std::string(e.what()));
    }
}

void server_connection_handshake_async(
    FizzServerConnection& conn,
    rust::Box<IoContext> context) {
    if (!conn.transport) {
        throw std::runtime_error("No transport available");
    }

    auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);

    class ServerHandshakeCallbackAsync
        : public fizz::server::AsyncFizzServer::HandshakeCallback {
        FizzServerConnection* conn_;
        rust::Box<IoContext> context_;

    public:
        ServerHandshakeCallbackAsync(
            FizzServerConnection* conn,
            rust::Box<IoContext> ctx)
            : conn_(conn), context_(std::move(ctx)) {}

        void fizzHandshakeSuccess(
            fizz::server::AsyncFizzServer* server) noexcept override {
            conn_->handshakeComplete = true;
            server->setReadCB(conn_);
            handle_io_result(std::move(context_), 0, rust::String(""));
        }

        void fizzHandshakeError(
            fizz::server::AsyncFizzServer*,
            folly::exception_wrapper ex) noexcept override {
            conn_->errorMessage = ex.what().toStdString();
            handle_io_result(
                std::move(context_), 0, rust::String(conn_->errorMessage));
        }

        void fizzHandshakeAttemptFallback(
            fizz::server::AttemptVersionFallback) noexcept override {
            conn_->errorMessage = "Version fallback attempted";
            handle_io_result(
                std::move(context_), 0, rust::String(conn_->errorMessage));
        }
    };

    auto* callback =
        new ServerHandshakeCallbackAsync(&conn, std::move(context));

    try {
        conn.evb->runInEventBaseThreadAndWait([&]() {
            transport->accept(callback);
        });
    } catch (...) {
        delete callback;
        throw;
    }
}

bool server_connection_is_open(const FizzServerConnection& conn) {
    if (!conn.handshakeComplete) {
        return false;
    }

    try {
        auto* transport = static_cast<const fizz::server::AsyncFizzServer*>(conn.transport);
        return transport != nullptr && transport->good();
    } catch (...) {
        return false;
    }
}

void server_connection_close(FizzServerConnection& conn) {
    try {
        if (conn.transport) {
            auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
            if (transport->good()) {
              conn.evb->runInEventBaseThreadAndWait([&]() {
                  transport->close();
              });
            }
        }

        // Stop EventBase thread and join it
        if (conn.evb_thread && conn.evb_thread->joinable()) {
            // Signal EventBase to terminate
            conn.evb->terminateLoopSoon();
            // Wait for thread to finish
            conn.evb_thread->join();
            conn.evb_thread.reset();
        }
    } catch (const std::exception& e) {
        // Log error but don't throw on cleanup
        LOG(WARNING) << "Error closing connection: " << e.what();
    }
}

size_t server_connection_read(
    FizzServerConnection& conn,
    rust::Slice<uint8_t> buf) {
    try {
        if (!conn.handshakeComplete) {
            throw std::runtime_error("Cannot read: handshake not complete");
        }

        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }

        std::lock_guard<std::mutex> lock(conn.read_mutex);
        auto bytesRead_ = conn.bytesRead.load();
        if (bytesRead_ == 0) {
            return 0;
        }

        size_t toRead = std::min(bytesRead_, buf.size());
        auto data = conn.readBufQueue_.split(toRead);

        size_t copied = 0;
        for (const auto& bufNode : *data) {
            size_t toCopy = std::min(bufNode.size(), buf.size() - copied);
            std::memcpy(const_cast<uint8_t*>(buf.data()) + copied, bufNode.data(), toCopy);
            copied += toCopy;
        }

        conn.bytesRead -= toRead;
        return copied;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to read: " + std::string(e.what()));
    }
}

ReadOutcome server_connection_read_or_status(
    FizzServerConnection& conn,
    rust::Slice<uint8_t> buf) {
    if (!conn.handshakeComplete) {
        throw std::runtime_error("Cannot read: handshake not complete");
    }
    if (!conn.transport) {
        throw std::runtime_error("No transport available");
    }

    std::lock_guard<std::mutex> lock(conn.read_mutex);
    auto bytesRead_ = conn.bytesRead.load();
    if (bytesRead_ == 0) {
        return ReadOutcome{0, conn.readEof.load(std::memory_order_acquire)};
    }

    size_t toRead = std::min(bytesRead_, buf.size());
    auto data = conn.readBufQueue_.split(toRead);

    size_t copied = 0;
    for (const auto& bufNode : *data) {
        size_t toCopy = std::min(bufNode.size(), buf.size() - copied);
        std::memcpy(const_cast<uint8_t*>(buf.data()) + copied, bufNode.data(), toCopy);
        copied += toCopy;
    }

    conn.bytesRead -= toRead;
    return ReadOutcome{static_cast<uint64_t>(copied), false};
}


size_t server_read_size_hint(FizzServerConnection& conn) {
    return conn.bytesRead;
}

bool server_connection_read_eof(const FizzServerConnection& conn) {
    return conn.readEof.load(std::memory_order_acquire);
}

namespace {
// Heap-allocated, self-deleting write callback. Records errors on the conn
// for the next `server_connection_write` to observe.
class AsyncServerWriteCallback
    : public folly::AsyncTransportWrapper::WriteCallback {
    FizzServerConnection* conn_;
public:
    explicit AsyncServerWriteCallback(FizzServerConnection* conn) : conn_(conn) {}

    void writeSuccess() noexcept override {
        delete this;
    }

    void writeErr(
        size_t /*bytesWritten*/,
        const folly::AsyncSocketException& ex) noexcept override {
        {
            std::lock_guard<std::mutex> lock(conn_->writeErrorMutex);
            conn_->writeErrorMessage = std::string(ex.what());
        }
        conn_->writeError.store(true, std::memory_order_release);
        auto* transport =
            static_cast<fizz::server::AsyncFizzServer*>(conn_->transport);
        if (transport) {
            transport->closeNow();
        }
        delete this;
    }
};
}  // namespace

size_t server_connection_write(
    FizzServerConnection& conn,
    rust::Slice<const uint8_t> buf) {
      if (!conn.handshakeComplete) {
          throw std::runtime_error("Cannot write: handshake not complete");
      }

      if (!conn.transport) {
          throw std::runtime_error("No transport available");
      }

      // Surface any error from a prior fire-and-forget write.
      if (conn.writeError.load(std::memory_order_acquire)) {
          std::lock_guard<std::mutex> lock(conn.writeErrorMutex);
          throw std::runtime_error("Write failed: " + conn.writeErrorMessage);
      }

      auto* transport = static_cast<fizz::server::AsyncFizzServer*>(conn.transport);
      auto buf_ = folly::IOBuf::copyBuffer(buf.data(), buf.size());
      auto size = buf.size();
      auto* cb = new AsyncServerWriteCallback(&conn);

      conn.evb->runInEventBaseThread(
          [transport, cb, b = std::move(buf_)]() mutable {
              transport->writeChain(cb, std::move(b));
          });

      return size;
}

void set_server_read_waker(
    FizzServerConnection& conn,
    rust::Box<ReadWaker> waker) {
    conn.read_waker = std::move(waker);
}
