/*
 * credentials_ffi.cpp
 *
 * Implementation of delegated credential generation and verification FFI functions.
 */

#define GLOG_USE_GLOG_EXPORT

#include "ffi/credentials_ffi.h"
#include "ffi/certificates_ffi.h"
#include "ffi/util.h"
#include "fizz_rs/src/bridge.rs.h"
#include <fizz/protocol/Certificate.h>
#include <fizz/backend/openssl/certificate/OpenSSLSelfCertImpl.h>
#include <fizz/extensions/delegatedcred/Types.h>
#include <folly/ssl/OpenSSLPtrTypes.h>
#include <fizz/backend/openssl/certificate/CertUtils.h>
#include <fizz/extensions/delegatedcred/DelegatedCredentialUtils.h>
#include <fizz/extensions/delegatedcred/Serialization.h>
#include <fizz/protocol/CertificateVerifier.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>

// Helper: Convert PEM to SelfCert
static std::shared_ptr<fizz::SelfCert> pemToSelfCert(
    const std::string& certPem,
    const std::string& keyPem) {

    // Parse certificate
    folly::ssl::BioUniquePtr certBio(BIO_new_mem_buf(certPem.data(), certPem.size()));
    X509* cert = PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr);
    if (!cert) {
        throw std::runtime_error("Failed to parse certificate PEM");
    }
    folly::ssl::X509UniquePtr certPtr(cert);

    // Parse private key
    folly::ssl::BioUniquePtr keyBio(BIO_new_mem_buf(keyPem.data(), keyPem.size()));
    EVP_PKEY* key = PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr);
    if (!key) {
        throw std::runtime_error("Failed to parse private key PEM");
    }
    folly::ssl::EvpPkeyUniquePtr keyPtr(key);

    // Create SelfCert
    std::vector<folly::ssl::X509UniquePtr> certs;
    certs.push_back(std::move(certPtr));

    return std::make_shared<fizz::openssl::OpenSSLSelfCertImpl<fizz::openssl::KeyType::P256>>(
        std::move(keyPtr), std::move(certs));
}

// Helper: Convert EVP_PKEY to PEM string
static std::string keyToPem(EVP_PKEY* key) {
    folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        throw std::runtime_error("Failed to write private key to BIO");
    }

    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    return std::string(mem->data, mem->length);
}

// Helper: Convert public key to DER hex
static std::string publicKeyToDerHex(EVP_PKEY* key) {
    unsigned char* derBuf = nullptr;
    int derLen = i2d_PUBKEY(key, &derBuf);
    if (derLen < 0) {
        throw std::runtime_error("Failed to encode public key to DER");
    }

    std::stringstream ss;
    for (int i = 0; i < derLen; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(derBuf[i]);
    }

    OPENSSL_free(derBuf);
    return ss.str();
}

// Helper: Generate EC P-256 keypair
static folly::ssl::EvpPkeyUniquePtr generateEcP256Key() {
    folly::ssl::EvpPkeyCtxUniquePtr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        throw std::runtime_error("Failed to initialize keygen");
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0) {
        throw std::runtime_error("Failed to set curve to P-256");
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &key) <= 0) {
        throw std::runtime_error("Failed to generate EC key");
    }

    return folly::ssl::EvpPkeyUniquePtr(key);
}

// Helper: Serialize DelegatedCredential to hex string
static std::string serializeDelegatedCredential(const fizz::extensions::DelegatedCredential& cred) {
    std::stringstream ss;

    // Serialize valid_time (4 bytes)
    uint32_t vt = cred.valid_time;
    ss << std::hex << std::setw(8) << std::setfill('0') << vt;

    // Serialize expected_verify_scheme (2 bytes)
    uint16_t evs = static_cast<uint16_t>(cred.expected_verify_scheme);
    ss << std::hex << std::setw(4) << std::setfill('0') << evs;

    // Serialize public_key (length + data as hex)
    auto pkData = cred.public_key->coalesce();
    ss << std::hex << std::setw(8) << std::setfill('0') << pkData.size();
    for (size_t i = 0; i < pkData.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(static_cast<unsigned char>(pkData[i]));
    }

    // Serialize credential_scheme (2 bytes)
    uint16_t cs = static_cast<uint16_t>(cred.credential_scheme);
    ss << std::hex << std::setw(4) << std::setfill('0') << cs;

    // Serialize signature (length + data as hex)
    auto sigData = cred.signature->coalesce();
    ss << std::hex << std::setw(8) << std::setfill('0') << sigData.size();
    for (size_t i = 0; i < sigData.size(); ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(static_cast<unsigned char>(sigData[i]));
    }

    return ss.str();
}

// ============================================================================
// Credential Generation Functions
// ============================================================================

std::unique_ptr<FizzCredentialGenerator> new_credential_generator(
    const CertificateData& parent_cert) {
    try {
        // Parse certificate and key
        auto selfCert = pemToSelfCert(
            std::string(parent_cert.cert_pem),
            std::string(parent_cert.key_pem));

        // Parse key separately for storage
        folly::ssl::BioUniquePtr keyBio(BIO_new_mem_buf(
            parent_cert.key_pem.data(),
            parent_cert.key_pem.size()));
        EVP_PKEY* key = PEM_read_bio_PrivateKey(keyBio.get(), nullptr, nullptr, nullptr);
        if (!key) {
            throw std::runtime_error("Failed to parse private key");
        }

        // Verify parent certificate has DC extensions
        fizz::extensions::DelegatedCredentialUtils::checkExtensions(selfCert->getX509());

        auto generator = std::make_unique<FizzCredentialGenerator>();
        generator->parentCert = std::move(selfCert);
        generator->parentKey = folly::ssl::EvpPkeyUniquePtr(key);
        generator->validitySeconds = std::chrono::seconds(7 * 24 * 3600); // Default 7 days

        return generator;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to create credential generator: " + std::string(e.what()));
    }
}

ServiceCredential generate_delegated_credential(
    const FizzCredentialGenerator& generator,
    rust::Str service_name,
    uint32_t valid_seconds) {
    try {
        std::string serviceName(service_name.data(), service_name.size());

        // Generate new EC P-256 key for the credential
        auto credKey = generateEcP256Key();

        // Get signature schemes
        auto parentKeyType = fizz::openssl::CertUtils::getKeyType(generator.parentKey);
        auto parentSigSchemes = fizz::openssl::CertUtils::getSigSchemes(parentKeyType);
        auto credKeyType = fizz::openssl::CertUtils::getKeyType(credKey);
        auto credSigSchemes = fizz::openssl::CertUtils::getSigSchemes(credKeyType);

        if (parentSigSchemes.empty() || credSigSchemes.empty()) {
            throw std::runtime_error("No valid signature schemes available");
        }

        auto parentSigScheme = parentSigSchemes[0];
        auto credSigScheme = credSigSchemes[0];

        // Generate the delegated credential
        auto credential = fizz::extensions::DelegatedCredentialUtils::generateCredential(
            generator.parentCert,
            generator.parentKey,
            credKey,
            parentSigScheme,
            credSigScheme,
            fizz::CertificateVerifyContext::ServerDelegatedCredential,
            std::chrono::seconds(valid_seconds));

        // Store public key DER and private key PEM
        std::string publicKeyDer = publicKeyToDerHex(credKey.get());
        std::string keyPEM = keyToPem(credKey.get());

        // Generate credential PEM
        std::string credentialPEM = fizz::extensions::generateDelegatedCredentialPEM(
            fizz::extensions::DelegatedCredentialMode::Server,
            std::move(credential),
            keyPEM);

        // Re-generate credential for storage (since we moved it)
        auto credential2 = fizz::extensions::DelegatedCredentialUtils::generateCredential(
            generator.parentCert,
            generator.parentKey,
            credKey,
            parentSigScheme,
            credSigScheme,
            fizz::CertificateVerifyContext::ServerDelegatedCredential,
            std::chrono::seconds(valid_seconds));

        // Calculate timestamps
        auto now = std::chrono::system_clock::now();
        auto expiresAt = now + std::chrono::seconds(valid_seconds);
        uint64_t createdTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();
        uint64_t expiresTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
            expiresAt.time_since_epoch()).count();

        // Serialize credential fields
        auto pkData = credential2.public_key->coalesce();
        std::string pkHex = bytes_to_hex_lower(pkData);

        auto sigData = credential2.signature->coalesce();
        std::string sigHex = bytes_to_hex_lower(sigData);

        // Build ServiceCredential
        ServiceCredential result;
        result.service_name = serviceName;

        result.credential.valid_time = credential2.valid_time;
        result.credential.expected_verify_scheme = static_cast<uint16_t>(credential2.expected_verify_scheme);
        result.credential.public_key_der = pkHex;
        result.credential.credential_scheme = static_cast<uint16_t>(credential2.credential_scheme);
        result.credential.signature = sigHex;

        result.private_key_pem = keyPEM;
        result.public_key_der = publicKeyDer;
        result.created_at = createdTimestamp;
        result.expires_at = expiresTimestamp;
        result.credential_pem = credentialPEM;

        return result;
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to generate delegated credential: " + std::string(e.what()));
    }
}

bool verify_delegated_credential(
    const FizzCredentialGenerator& generator,
    const ServiceCredential& credential) {
    try {
        // Reconstruct the DelegatedCredential from ServiceCredential
        fizz::extensions::DelegatedCredential dc;
        dc.valid_time = credential.credential.valid_time;
        dc.expected_verify_scheme = static_cast<fizz::SignatureScheme>(
            credential.credential.expected_verify_scheme);
        dc.credential_scheme = static_cast<fizz::SignatureScheme>(
            credential.credential.credential_scheme);

        // Parse public key from hex
        std::string pkHex = std::string(credential.credential.public_key_der);
        std::vector<uint8_t> pkBytes;
        for (size_t i = 0; i < pkHex.length(); i += 2) {
            std::string byteStr = pkHex.substr(i, 2);
            pkBytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
        }
        dc.public_key = folly::IOBuf::copyBuffer(pkBytes.data(), pkBytes.size());

        // Parse signature from hex
        std::string sigHex = std::string(credential.credential.signature);
        std::vector<uint8_t> sigBytes;
        for (size_t i = 0; i < sigHex.length(); i += 2) {
            std::string byteStr = sigHex.substr(i, 2);
            sigBytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
        }
        dc.signature = folly::IOBuf::copyBuffer(sigBytes.data(), sigBytes.size());

        // Prepare signature buffer
        auto certDer = folly::ssl::OpenSSLCertUtils::derEncode(*generator.parentCert->getX509());
        auto signatureBuffer = fizz::extensions::DelegatedCredentialUtils::prepareSignatureBuffer(
            dc, std::move(certDer));

        // Create peer cert from parent cert
        auto peerCert = fizz::openssl::CertUtils::makePeerCert(generator.parentCert->getX509());

        // Verify the credential signature
        peerCert->verify(
            dc.credential_scheme,
            fizz::CertificateVerifyContext::ServerDelegatedCredential,
            signatureBuffer->coalesce(),
            dc.signature->coalesce());

        return true;
    } catch (const std::exception& e) {
        // Verification failed
        return false;
    }
}

rust::String delegated_credential_to_pem(const ServiceCredential& credential) {
    return rust::String(credential.credential_pem);
}

ServiceCredential load_delegated_credential_from_pem(rust::Str pem) {
    throw std::runtime_error("load_delegated_credential_from_pem not yet implemented");
}

VerificationInfo get_public_verification_info(const ServiceCredential& credential) {
    VerificationInfo info;
    info.service_name = credential.service_name;
    info.valid_time = credential.credential.valid_time;
    info.expected_verify_scheme = credential.credential.expected_verify_scheme;
    info.public_key_der = credential.public_key_der;
    info.expires_at = credential.expires_at;
    return info;
}

rust::String verification_info_to_json(const VerificationInfo& info) {
    std::stringstream ss;
    ss << "{"
       << "\"service_name\":\"" << std::string(info.service_name) << "\","
       << "\"valid_time\":" << info.valid_time << ","
       << "\"expected_verify_scheme\":" << info.expected_verify_scheme << ","
       << "\"public_key_der\":\"" << std::string(info.public_key_der) << "\","
       << "\"expires_at\":" << info.expires_at
       << "}";
    return rust::String(ss.str());
}

VerificationInfo verification_info_from_json(rust::Str json) {
    throw std::runtime_error("verification_info_from_json not yet implemented");
}
