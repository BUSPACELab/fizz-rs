/*
 * server_tls_ffi.h
 *
 * FFI wrapper for server-side TLS operations with delegated credentials.
 * This header is included by the CXX bridge.
 */

#pragma once

#define GLOG_USE_GLOG_EXPORT

// Include glog before folly to satisfy its requirements
#include <glog/logging.h>

#include <fizz/server/FizzServerContext.h>
#include <fizz/server/TicketTypes.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialCertManager.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/IOBufQueue.h>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <mutex>

// Forward declare shared structs from bridge
struct CertificateData;
struct CertificatePublic;
struct ServiceCredential;

// Opaque type for server TLS context
// Full definition is required for CXX UniquePtr operations
struct FizzServerContext {
    std::shared_ptr<fizz::server::FizzServerContext> ctx;
    std::unique_ptr<fizz::extensions::DelegatedCredentialCertManager> certManager;
    std::shared_ptr<fizz::server::TicketCipher> ticketCipher;
    std::vector<std::string> alpnProtocols;
};

// Opaque type for server TLS connection
// Full definition is required for CXX UniquePtr operations
struct FizzServerConnection : public folly::AsyncTransportWrapper::ReadCallback {
  public:
    // Destructor to ensure EventBase thread is cleaned up
    ~FizzServerConnection();
    void getReadBuffer(void** bufReturn, size_t* lenReturn) override;
    void readDataAvailable(size_t len) noexcept override;
    void readEOF() noexcept override;
    void readErr(const folly::AsyncSocketException& ex) noexcept override;
    std::shared_ptr<folly::EventBase> evb;
    std::unique_ptr<std::thread> evb_thread; // Thread running EventBase loop
    void* transport; // AsyncFizzServer* (void* to avoid header dependency)
    bool handshakeComplete;
    std::string errorMessage;
    int fd; // Socket file descriptor for cleanup

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
