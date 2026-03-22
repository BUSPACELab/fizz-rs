/*
 * client_tls_ffi.cpp
 *
 * Implementation of client-side TLS FFI functions with delegated credentials verification.
 */

#define GLOG_USE_GLOG_EXPORT

#include "ffi/client_tls_ffi.h"
#include "fizz_rs/src/bridge.rs.h"
#include <fizz/client/AsyncFizzClient.h>
#include <fizz/client/PskSerializationUtils.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialClientExtension.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialFactory.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/PeerDelegatedCredential.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/io/IOBufQueue.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <chrono>
#include <cstdio>
#include <thread>

// Helper: Load CA certificate from file
static std::vector<folly::ssl::X509UniquePtr> loadCACertificates(const std::string& caPath) {
    std::vector<folly::ssl::X509UniquePtr> caCerts;

    // Read CA certificate file
    std::ifstream file(caPath);
    if (!file) {
        throw std::runtime_error("Failed to open CA certificate file: " + caPath);
    }

    std::string pemData((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());

    // Parse PEM data into X509 certificate
    BIO* bio = BIO_new_mem_buf(pemData.data(), pemData.size());
    if (!bio) {
        throw std::runtime_error("Failed to create BIO for CA certificate");
    }

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        throw std::runtime_error("Failed to parse CA certificate from PEM");
    }

    caCerts.push_back(folly::ssl::X509UniquePtr(cert));
    return caCerts;
}

// Helper: Create certificate verifier from CA certificate path
static std::shared_ptr<fizz::DefaultCertificateVerifier> createCertificateVerifier(
    const std::string& caCertPath) {
    try {
        // Create X509 store for CA certificates
        folly::ssl::X509StoreUniquePtr store(X509_STORE_new());
        if (!store) {
            throw std::runtime_error("Failed to create X509_STORE");
        }

        // Load CA certificate from file into the store
        if (X509_STORE_load_locations(store.get(), caCertPath.c_str(), nullptr) == 0) {
            throw std::runtime_error("Failed to load CA certificate from: " + caCertPath);
        }

        // Create and return the certificate verifier
        return std::make_shared<fizz::DefaultCertificateVerifier>(
            fizz::VerificationContext::Client,
            std::move(store));
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create certificate verifier: " + std::string(e.what()));
    }
}

/// Hex-encode wire delegated-credential public key (same layout as `credentials_ffi.cpp`).
static std::string delegatedCredentialPublicKeyHex(
    const fizz::extensions::DelegatedCredential& dc) {
    auto pkData = dc.public_key->coalesce();
    std::string out;
    out.reserve(pkData.size() * 2);
    for (size_t i = 0; i < pkData.size(); ++i) {
        char buf[3];
        std::snprintf(
            buf,
            sizeof(buf),
            "%02x",
            static_cast<unsigned char>(pkData[i]));
        out += buf;
    }
    return out;
}

/// Returns empty string on success, otherwise a human-readable error.
static std::string verifyVerificationInfoAgainstPeerDelegatedCredential(
    const FizzClientConnection& conn,
    const fizz::extensions::PeerDelegatedCredential& peerDC) {
    const auto& dc = peerDC.getDelegatedCredential();

    if (delegatedCredentialPublicKeyHex(dc) != conn.expectedPublicKeyDerHex) {
        return "delegated credential public key does not match VerificationInfo";
    }
    if (dc.valid_time != conn.expectedValidTime) {
        return "delegated credential valid_time does not match VerificationInfo";
    }
    if (static_cast<uint16_t>(dc.expected_verify_scheme) != conn.expectedVerifyScheme) {
        return "delegated credential verify scheme does not match VerificationInfo";
    }

    folly::ssl::X509UniquePtr leafX509 = peerDC.getX509();
    auto expTp = fizz::extensions::DelegatedCredentialUtils::getCredentialExpiresTime(
        leafX509, dc);
    const uint64_t wireExpiresSec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(expTp.time_since_epoch())
            .count());
    if (wireExpiresSec != conn.expectedExpiresAt) {
        return "delegated credential expiry does not match VerificationInfo";
    }

    (void)conn.expectedServiceName;
    return {};
}

// ============================================================================
// FizzClientConnection Destructor
// ============================================================================

FizzClientConnection::~FizzClientConnection() {
    try {
      std::cout << "Invoking client destructor" << std::endl;
        // Stop EventBase thread if it's running
            if (evb_thread && evb_thread->joinable()) {
                if (evb) {
                    evb->terminateLoopSoon();
                }
                evb_thread->join();
            }
        // Clean up transport
    } catch (...) {
        // Swallow exceptions in destructor to avoid std::terminate
    }
}


void FizzClientConnection::getReadBuffer(void** bufReturn, size_t* lenReturn) {
  // Preallocate buffer in the queue - min 4096 bytes
  //

  // std::cout << "Client_side: About to acquire the lock" << std::endl;
  read_mutex.lock();
  pending_read_lock_numbers += 1;
  // std::cout << "Client_side: Acquired the lock" << std::endl;
  auto result = readBufQueue_.preallocate(40960, 65536);
  *bufReturn = result.first;
  *lenReturn = result.second;
}

void FizzClientConnection::readDataAvailable(size_t len) noexcept {
    // std::cout << "Client::readDataAvailable: Reading available data of size " << len << std::endl;
    // Commit the bytes that were read into the queue
    readBufQueue_.postallocate(len);
    bytesRead += len;
    //Wipe the number of held locks.
    size_t nb_lock_releases = pending_read_lock_numbers.exchange(0);
    // std::cout << "We will be releasing " << nb_lock_releases << " locks" << std::endl;
    for (int i=0; i < nb_lock_releases; i++) {
      read_mutex.unlock();
    }
}

void FizzClientConnection::readEOF() noexcept {
    readEof.store(true, std::memory_order_release);
    auto* transport_ = static_cast<fizz::client::AsyncFizzClient*>(transport);
    // std::cout << "Server closed connection" << std::endl;
    transport_->closeNow();
}

void FizzClientConnection::readErr(const folly::AsyncSocketException& ex) noexcept {
    errorMessage = ex.what();
    std::cerr << "Got error" << errorMessage << std::endl;
    auto* transport_ = static_cast<fizz::client::AsyncFizzClient*>(transport);
    transport_->closeNow();
}

// ============================================================================
// Client Context Creation
// ============================================================================

std::unique_ptr<FizzClientContext> new_client_tls_context(
    const VerificationInfo& verification_info,
    rust::Str ca_cert_path) {
    try {
        auto context = std::make_unique<FizzClientContext>();

        // Extract and store verification info fields as native C++ types
        context->serviceName = std::string(verification_info.service_name);
        context->validTime = verification_info.valid_time;
        context->expectedVerifyScheme = verification_info.expected_verify_scheme;
        context->publicKeyDer = std::string(verification_info.public_key_der);
        context->expiresAt = verification_info.expires_at;
        context->caCertPath = std::string(ca_cert_path);

        // Create Fizz client context
        context->ctx = std::make_shared<fizz::client::FizzClientContext>();

        // CRITICAL: Set DelegatedCredentialFactory to enable parsing and verification of DCs
        auto factory = std::make_shared<fizz::extensions::DelegatedCredentialFactory>();
        context->ctx->setFactory(factory);

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

        // Note: Certificate verification and delegated credential verification
        // will be configured when creating the AsyncFizzClient connection
        // The CA certificates and verification info are stored in the context
        // and will be used during connection establishment

        // Initialize ALPN and SNI (empty for now, can be set later)
        context->alpnProtocols = {};
        context->sniHostname = "";

        return context;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create client TLS context: " + std::string(e.what()));
    }
}

void client_context_set_alpn_protocols(
    FizzClientContext& ctx,
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

void client_context_set_sni(
    FizzClientContext& ctx,
    rust::Str hostname) {
    try {
        ctx.sniHostname = std::string(hostname);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to set SNI hostname: " + std::string(e.what()));
    }
}

// ============================================================================
// Client Connection Management
// ============================================================================

std::unique_ptr<FizzClientConnection> client_connect(
    const FizzClientContext& ctx,
    int32_t fd,
    rust::Str hostname) {
    try {
        auto conn = std::make_unique<FizzClientConnection>();

        // Create EventBase for this connection
        // TODO(OPTIMIZATION): Use a shared EventBase pool instead of creating one per connection
        // This would reduce memory overhead and improve performance for many concurrent connections
        conn->evb = std::make_shared<folly::EventBase>();
        conn->fd = fd;
        conn->handshakeComplete = false;
        conn->errorMessage.clear();
        conn->peerCertPem.clear();

        // CRITICAL: Create certificate verifier with CA certificate
        conn->caCertPath = ctx.caCertPath;
        conn->verifier = createCertificateVerifier(ctx.caCertPath);

        // CRITICAL: Create delegated credential extension with supported signature schemes
        // This advertises DC support to the server in ClientHello
        std::vector<fizz::SignatureScheme> dcSigSchemes = {
            fizz::SignatureScheme::ecdsa_secp256r1_sha256,
            fizz::SignatureScheme::ecdsa_secp384r1_sha384,
            fizz::SignatureScheme::ecdsa_secp521r1_sha512,
            fizz::SignatureScheme::rsa_pss_sha256
        };
        conn->dcExtension = std::make_shared<fizz::extensions::DelegatedCredentialClientExtension>(
            dcSigSchemes);
        conn->bytesRead = 0;

        conn->expectedServiceName = ctx.serviceName;
        conn->expectedValidTime = ctx.validTime;
        conn->expectedVerifyScheme = ctx.expectedVerifyScheme;
        conn->expectedPublicKeyDerHex = ctx.publicKeyDer;
        conn->expectedExpiresAt = ctx.expiresAt;

        // Create AsyncSocket from file descriptor
        // Note: AsyncSocket takes ownership of the FD
        folly::NetworkSocket networkSocket(fd);
        auto socket = folly::AsyncSocket::newSocket(conn->evb.get(), networkSocket);

        // Create AsyncFizzClient with the socket, context, and DC extension
        auto fizzClient = fizz::client::AsyncFizzClient::UniquePtr(
            new fizz::client::AsyncFizzClient(
                std::move(socket),
                ctx.ctx,
                conn->dcExtension  // Pass DC extension to enable delegated credentials
            )
        );

        // Store SNI hostname for later use during handshake
        std::string sniHostname = std::string(hostname);
        if (sniHostname.empty() && !ctx.sniHostname.empty()) {
            sniHostname = ctx.sniHostname;
        }

        // Store SNI in connection for use during handshake
        // Note: SNI is set during connect() call, not here

        // Store transport pointer (cast to void* to avoid header dependency)
        conn->transport = fizzClient.release();

        // Store SNI for handshake (hack: reuse peerCertPem temporarily)
        conn->peerCertPem = sniHostname;

        // Start EventBase thread to process async operations
        // This thread will run the event loop until the connection is closed
        auto evb_ptr = conn->evb.get();
        conn->evb_thread = std::make_unique<std::thread>([evb_ptr]() {
            // Run the EventBase loop forever (until terminateLoopSoon() is called)
            evb_ptr->loopForever();
        });

        return conn;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to connect: " + std::string(e.what()));
    }
}

void client_connection_handshake(FizzClientConnection& conn) {
    try {
        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }

        // Get context to access CA cert path (stored in connection via hack)
        // Note: We need the CA cert path which should be stored somewhere accessible
        // For now, we'll extract it from the transport's context
        auto* transport = static_cast<fizz::client::AsyncFizzClient*>(conn.transport);

        // Handshake callback implementation
        class ClientHandshakeCallback : public fizz::client::AsyncFizzClient::HandshakeCallback {
            bool& complete_;
            std::string& error_;
            std::string& peerCert_;
            FizzClientConnection* conn_;


        public:
            ClientHandshakeCallback(bool& complete, std::string& error, std::string& peerCert, FizzClientConnection* conn)
                : complete_(complete), error_(error), peerCert_(peerCert), conn_(conn) {}

            void fizzHandshakeSuccess(fizz::client::AsyncFizzClient* client) noexcept override {
                try {
                    const auto& state = client->getState();
                    auto serverCert = state.serverCert();
                    if (!serverCert) {
                        error_ = "No server certificate after handshake";
                        return;
                    }

                    const auto* peerDC =
                        dynamic_cast<const fizz::extensions::PeerDelegatedCredential*>(
                            serverCert.get());
                    if (!peerDC) {
                        error_ = "Server did not present a delegated credential certificate";
                        return;
                    }

                    std::string mismatch =
                        verifyVerificationInfoAgainstPeerDelegatedCredential(*conn_, *peerDC);
                    if (!mismatch.empty()) {
                        error_ = std::move(mismatch);
                        client->closeNow();
                        return;
                    }

                    peerCert_ = "[Certificate extracted successfully]";
                    client->setReadCB(conn_);
                    complete_ = true;
                } catch (const std::exception& e) {
                    error_ = std::string("Failed to verify delegated credential: ") + e.what();
                }
            }

            void fizzHandshakeError(
                fizz::client::AsyncFizzClient*,
                folly::exception_wrapper ex) noexcept override {
                error_ = ex.what().toStdString();
            }
        };

        // Create callback (ownership transferred to Fizz)
        auto* callback = new ClientHandshakeCallback(
            conn.handshakeComplete,
            conn.errorMessage,
            conn.peerCertPem,
            &conn
        );

        // Extract SNI from peerCertPem (where we temporarily stored it)
        std::string sniHostname = conn.peerCertPem;
        conn.peerCertPem.clear(); // Clear for actual certificate data

        // CRITICAL: Create proper certificate verifier with CA certificate
        // Note: CA cert path should be accessible via the context
        // For now, we extract it from the Fizz context (stored during context creation)
        std::shared_ptr<const fizz::CertificateVerifier> verifier = conn.verifier;

        // Start handshake (Fizz takes ownership of callback)
        // Parameters: callback, verifier, SNI hostname, PSK identity, ECH configs, handshake timeout
        folly::Optional<std::string> sni = sniHostname.empty() ?
            folly::none : folly::Optional<std::string>(sniHostname);

        // Start handshake on EventBase thread
        conn.evb->runInEventBaseThreadAndWait([&]() {
            transport->connect(
                callback,
                verifier,
                sni,
                folly::none, // PSK identity
                folly::none, // ECH configs
                std::chrono::milliseconds(30000) // 30 second handshake timeout
            );
        });

        // // Wait for handshake to complete (processed by EventBase thread)
        auto startTime = std::chrono::steady_clock::now();
        const auto timeout = std::chrono::seconds(30); // 30 second timeout

        while (!conn.handshakeComplete && conn.errorMessage.empty()) {
            // Check timeout
            auto elapsed = std::chrono::steady_clock::now() - startTime;
            if (elapsed > timeout) {
                throw std::runtime_error("Handshake timed out after 30 seconds");
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
        throw std::runtime_error("Client handshake failed: " + std::string(e.what()));
    }
}

bool client_connection_is_open(const FizzClientConnection& conn) {
    if (!conn.handshakeComplete) {
        return false;
    }

    try {
        auto* transport = static_cast<const fizz::client::AsyncFizzClient*>(conn.transport);
        return transport != nullptr && transport->good();
    } catch (...) {
        return false;
    }
}

void client_connection_close(FizzClientConnection& conn) {
    try {
        if (conn.transport) {
            auto* transport = static_cast<fizz::client::AsyncFizzClient*>(conn.transport);
            if (transport->good()) {
              conn.evb->runInEventBaseThreadAndWait([&]() {
                  transport->close();
              });
            }
            // Note: Don't delete transport here, it will be cleaned up by EventBase
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

size_t client_connection_read(
    FizzClientConnection& conn,
    rust::Slice<uint8_t> buf) {
    try {
        if (!conn.handshakeComplete) {
            throw std::runtime_error("Cannot read: handshake not complete");
        }

        if (!conn.transport) {
            throw std::runtime_error("No transport available");
            
        }

        std::lock_guard<std::recursive_mutex> lock(conn.read_mutex);
        // Consume bytes from the queue and copy to Rust buffer
        size_t bytesRead_ = conn.bytesRead.load();
        if (bytesRead_ == 0) {
            return 0;
        }

        // std::cout << "C++ client read: Holding " << bytesRead_ << " bytes up for read" << std::endl;

        // Split the requested bytes from the queue
        size_t toRead = std::min(bytesRead_, buf.size());
        auto data = conn.readBufQueue_.split(toRead);

        // std::cout << "C++ client read: Intending to read " << toRead << " bytes" << std::endl;

        // Copy data from IOBuf chain to Rust buffer
        size_t copied = 0;
        for (const auto& bufNode : *data) {
            size_t toCopy = std::min(bufNode.size(), buf.size() - copied);
            std::memcpy(const_cast<uint8_t*>(buf.data()) + copied, bufNode.data(), toCopy);
            copied += toCopy;
        }

        // std::cout << "C++ client read: Ended up reading " << copied << " bytes" << std::endl;

        conn.bytesRead -= toRead;
        return copied;

    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to read: " + std::string(e.what()));
    }
}

size_t client_read_size_hint(FizzClientConnection& conn) {
    return conn.bytesRead;
}

bool client_connection_read_eof(const FizzClientConnection& conn) {
    return conn.readEof.load(std::memory_order_acquire);
}

size_t client_connection_write(
    FizzClientConnection& conn,
    rust::Slice<const uint8_t> buf) {
        if (!conn.handshakeComplete) {
            throw std::runtime_error("Cannot write: handshake not complete");
        }

        if (!conn.transport) {
            throw std::runtime_error("No transport available");
        }

        auto* transport = static_cast<fizz::client::AsyncFizzClient*>(conn.transport);
        // std::cout << "Client: Sync Write" << std::endl;
        //
        auto buf_ = folly::IOBuf::copyBuffer(buf.data(), buf.size());

        auto write_length = buf_->length();

        class WriteCallback : public folly::AsyncTransportWrapper::WriteCallback {
        std::string& ex_string_;
        bool& error_;
        fizz::client::AsyncFizzClient* transport_;

        public:
            WriteCallback(std::string& ex_string, bool& error, fizz::client::AsyncFizzClient* transport): ex_string_(ex_string), error_(error), transport_(transport) {}

            void writeSuccess() noexcept override {
            }

            void writeErr(size_t /*bytesWritten*/, const folly::AsyncSocketException& ex) noexcept override {
                std::cerr << "Write failed" << std::endl;
                ex_string_ = std::string(ex.what());
                error_ = true;
                transport_->closeNow();
            }
      };

        std::string err_str;
        bool error = false;

        auto wr_cb = WriteCallback(err_str, error, transport);
        conn.evb->runInEventBaseThreadAndWait([&]() {
          transport->writeChain(&wr_cb, std::move(buf_));
        });


        if (error) {
          throw std::runtime_error("Write failed" + err_str);
        }
        return write_length;
}

rust::String client_connection_peer_cert(const FizzClientConnection& conn) {
    try {
        if (!conn.handshakeComplete) {
            throw std::runtime_error("Handshake not complete");
        }

        if (conn.peerCertPem.empty()) {
            throw std::runtime_error("No peer certificate available");
        }

        return rust::String(conn.peerCertPem);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to get peer certificate: " + std::string(e.what()));
    }
}
