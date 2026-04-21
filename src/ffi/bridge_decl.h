/*
 * bridge_decl.h
 *
 * Function declarations for CXX bridge. This header is included by the CXX-generated
 * code AFTER rust:: types are defined. It provides the function signatures that
 * our .cpp files will implement.
 *
 * NOTE: This header should ONLY be included AFTER rust:: types are available.
 */

#pragma once

// Only define these declarations when included in the right context
// This file should be included at the END of our type definition headers
#ifndef FIZZ_RS_BRIDGE_DECL_H
#define FIZZ_RS_BRIDGE_DECL_H

// Forward declare the types if not already defined
struct CertificateData;
struct CertificatePublic;
struct ServiceCredential;
struct VerificationInfo;
struct FizzPrivateKey;
struct FizzCredentialGenerator;
struct FizzServerContext;
struct FizzServerConnection;
struct FizzClientContext;
struct FizzClientConnection;

namespace rust {
inline namespace cxxbridge1 {
class String;
class Str;
template <typename T>
class Vec;
template <typename T>
class Slice;
template <typename T>
class Fn;
template <typename T>
class Box;
} // namespace cxxbridge1
} // namespace rust

// Certificate FFI function declarations
CertificateData load_certificate_from_pem(rust::Str cert_pem, rust::Str key_pem);
CertificateData load_certificate_from_file(rust::Str cert_path, rust::Str key_path);
CertificatePublic load_certificate_public_from_pem(rust::Str cert_pem);
CertificatePublic load_certificate_public_from_file(rust::Str cert_path);
rust::Vec<uint16_t> get_certificate_sig_schemes(const CertificateData& cert_data);
rust::String certificate_to_pem(const CertificateData& cert_data);

std::unique_ptr<FizzPrivateKey> load_private_key_from_pem(rust::Str key_pem);
std::unique_ptr<FizzPrivateKey> generate_ec_p256_keypair();
rust::String private_key_to_pem(const FizzPrivateKey& key);
rust::String get_public_key_der(const FizzPrivateKey& key);

// Credential FFI function declarations
std::unique_ptr<FizzCredentialGenerator> new_credential_generator(const CertificateData& parent_cert);
ServiceCredential generate_delegated_credential(
    const FizzCredentialGenerator& generator,
    rust::Str service_name,
    uint32_t valid_seconds);
bool verify_delegated_credential(
    const FizzCredentialGenerator& generator,
    const ServiceCredential& credential);
rust::String delegated_credential_to_pem(const ServiceCredential& credential);
ServiceCredential load_delegated_credential_from_pem(rust::Str pem);
VerificationInfo get_public_verification_info(const ServiceCredential& credential);
rust::String verification_info_to_json(const VerificationInfo& info);
VerificationInfo verification_info_from_json(rust::Str json);

// Server TLS FFI function declarations
std::unique_ptr<FizzServerContext> new_server_tls_context(
    const CertificatePublic& parent_cert,
    const ServiceCredential& delegated_cred);
void server_context_set_alpn_protocols(
    FizzServerContext& ctx,
    rust::Vec<rust::String> protocols);
std::unique_ptr<FizzServerConnection> server_accept_connection(
    const FizzServerContext& ctx,
    int32_t fd);
void server_connection_handshake(FizzServerConnection& conn);
bool server_connection_is_open(const FizzServerConnection& conn);
void server_connection_close(FizzServerConnection& conn);
size_t server_connection_read(
    FizzServerConnection& conn,
    rust::Slice<uint8_t> buf);
size_t server_read_size_hint(FizzServerConnection& conn);
bool server_connection_read_eof(const FizzServerConnection& conn);
size_t server_connection_write(
    FizzServerConnection& conn,
    rust::Slice<const uint8_t> buf);

// Client TLS FFI function declarations
std::unique_ptr<FizzClientContext> new_client_tls_context(
    const VerificationInfo& verification_info,
    rust::Str ca_cert_path);
void client_context_set_alpn_protocols(
    FizzClientContext& ctx,
    rust::Vec<rust::String> protocols);
void client_context_set_sni(
    FizzClientContext& ctx,
    rust::Str hostname);
std::unique_ptr<FizzClientConnection> client_connect(
    const FizzClientContext& ctx,
    int32_t fd,
    rust::Str hostname);
void client_connection_handshake(FizzClientConnection& conn);
bool client_connection_is_open(const FizzClientConnection& conn);
void client_connection_close(FizzClientConnection& conn);
size_t client_connection_read(
    FizzClientConnection& conn,
    rust::Slice<uint8_t> buf);
size_t client_read_size_hint(FizzClientConnection& conn);
bool client_connection_read_eof(const FizzClientConnection& conn);
size_t client_connection_write(
    FizzClientConnection& conn,
    rust::Slice<const uint8_t> buf);
rust::String client_connection_peer_cert(const FizzClientConnection& conn);

// Forward declare IoContext from Rust
// struct IoContext;

// Async server TLS FFI function declarations (channel-based)
// void server_connection_handshake_async(
//     FizzServerConnection& conn,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);
// void server_connection_read_async(
//     FizzServerConnection& conn,
//     rust::Slice<uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);
// void server_connection_copy_read_data(
//     FizzServerConnection& conn,
//     rust::Slice<uint8_t> dest);
// void server_connection_write_async(
//     FizzServerConnection& conn,
//     rust::Slice<const uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);

// Async client TLS FFI function declarations (channel-based)
// void client_connection_handshake_async(
//     FizzClientConnection& conn,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);
// void client_connection_read_async(
//     FizzClientConnection& conn,
//     rust::Slice<uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);
// void client_connection_copy_read_data(
//     FizzClientConnection& conn,
//     rust::Slice<uint8_t> dest);
// void client_connection_write_async(
//     FizzClientConnection& conn,
//     rust::Slice<const uint8_t> buf,
//     rust::Fn<void(rust::Box<IoContext>, size_t, rust::String)> callback,
//     rust::Box<IoContext> context);

#endif // FIZZ_RS_BRIDGE_DECL_H
