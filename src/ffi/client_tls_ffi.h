/*
 * client_tls_ffi.h
 *
 * FFI wrapper for client-side TLS operations with delegated credentials verification.
 * This header is included by the CXX bridge.
 */

#pragma once

#define GLOG_USE_GLOG_EXPORT

// Include glog before folly to satisfy its requirements
#include <glog/logging.h>

#include <fizz/client/FizzClientContext.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialClientExtension.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/IOBufQueue.h>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <mutex>

// Forward declare shared structs from bridge
struct VerificationInfo;

// Opaque type for client TLS context
// Full definition is required for CXX UniquePtr operations
struct FizzClientContext {
    std::shared_ptr<fizz::client::FizzClientContext> ctx;
    // Store verification info fields as native C++ types
    std::string serviceName;
    uint32_t validTime;
    uint16_t expectedVerifyScheme;
    std::string publicKeyDer;
    uint64_t expiresAt;
    // Other context data
    std::string caCertPath;
    std::vector<std::string> alpnProtocols;
    std::string sniHostname;
};

// Forward declare types to avoid circular includes
namespace fizz {
    class CertificateVerifier;
    namespace extensions {
        class DelegatedCredentialClientExtension;
    }
}

// Opaque type for client TLS connection
// Full definition is required for CXX UniquePtr operations
struct FizzClientConnection : public folly::AsyncTransportWrapper::ReadCallback {
  public:
    // Destructor to ensure EventBase thread is cleaned up
    ~FizzClientConnection();
    void getReadBuffer(void** bufReturn, size_t* lenReturn) override;
    void readDataAvailable(size_t len) noexcept override;
    void readEOF() noexcept override;
    void readErr(const folly::AsyncSocketException& ex) noexcept override;

    std::shared_ptr<folly::EventBase> evb;
    std::unique_ptr<std::thread> evb_thread; // Thread running EventBase loop
    void* transport; // AsyncFizzClient* (void* to avoid header dependency)
    bool handshakeComplete;
    std::string errorMessage;
    int fd; // Socket file descriptor for cleanup
    std::string peerCertPem;

    // CRITICAL: Certificate verifier and delegated credential extension
    // These must be stored in the connection to be used during handshake
    std::shared_ptr<const fizz::CertificateVerifier> verifier;
    std::shared_ptr<fizz::extensions::DelegatedCredentialClientExtension> dcExtension;
    std::string caCertPath; // Needed to create verifier during handshake

    /// Out-of-band expectations from [`VerificationInfo`] (copied from context at connect).
    std::string expectedServiceName;
    uint32_t expectedValidTime{0};
    uint16_t expectedVerifyScheme{0};
    std::string expectedPublicKeyDerHex;
    uint64_t expectedExpiresAt{0};

    // Pending read data (owned by C++ to avoid Rust buffer lifetime issues)
    std::vector<uint8_t> pending_read_data;
    std::recursive_mutex read_mutex;
    std::atomic<size_t> pending_read_lock_numbers;

    // Read buffer queue for proper buffer management
    folly::IOBufQueue readBufQueue_{folly::IOBufQueue::cacheChainLength()};
    std::atomic<size_t> bytesRead;
    /// Set when `readEOF()` is invoked (peer closed / no more application data).
    std::atomic<bool> readEof{false};
};

// Include function declarations (uses forward-declared rust:: types)
#include "ffi/bridge_decl.h"
