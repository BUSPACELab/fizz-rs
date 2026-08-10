#include "credential.h"

#include <iostream>

#include "crypto_utils.h"

namespace sidecar {

namespace {

void verifyCredential(std::shared_ptr<fizz::SelfCert> parentCert,
                      const fizz::extensions::DelegatedCredential& credential) {
  try {
    // Prepare the signature buffer (what was signed)
    auto certDer =
        folly::ssl::OpenSSLCertUtils::derEncode(*parentCert->getX509());
    auto signatureBuffer =
        fizz::extensions::DelegatedCredentialUtils::prepareSignatureBuffer(
            credential, std::move(certDer));

    // Create a peer certificate from parent cert to verify signature
    auto peerCert =
        fizz::openssl::CertUtils::makePeerCert(parentCert->getX509());

    // Verify the credential signature using parent cert's public key
    peerCert->verify(credential.credential_scheme,
                     fizz::CertificateVerifyContext::ServerDelegatedCredential,
                     signatureBuffer->coalesce(),
                     credential.signature->coalesce());
  } catch (const std::exception& e) {
    throw std::runtime_error("Credential self-verification failed: " +
                             std::string(e.what()));
  }
}

}  // namespace

std::pair<ServerCredential, ClientVerificationInfo> generateDelegatedCredential(
    std::shared_ptr<fizz::SelfCert> parentCert,
    folly::ssl::EvpPkeyUniquePtr parentKey,
    std::chrono::seconds validitySeconds) {
  // Generate a new private key for the delegated credential
  auto credKey = generateKeyPair();

  // Determine signature schemes
  auto parentKeyType = fizz::openssl::CertUtils::getKeyType(parentKey);
  auto parentSigSchemes =
      fizz::openssl::CertUtils::getSigSchemes(parentKeyType);
  auto credKeyType = fizz::openssl::CertUtils::getKeyType(credKey);
  auto credSigSchemes = fizz::openssl::CertUtils::getSigSchemes(credKeyType);

  if (parentSigSchemes.empty() || credSigSchemes.empty()) {
    throw std::runtime_error("No valid signature schemes available");
  }

  // Use the first available signature scheme for each
  auto parentSigScheme = parentSigSchemes[0];
  auto credSigScheme = credSigSchemes[0];

  // Generate the delegated credential
  fizz::extensions::DelegatedCredential credential =
      fizz::extensions::DelegatedCredentialUtils::generateCredential(
          parentCert, parentKey, credKey, parentSigScheme, credSigScheme,
          fizz::CertificateVerifyContext::ServerDelegatedCredential,
          validitySeconds);

  // verify the signature directly just as a sanity check.
  verifyCredential(parentCert, credential);

  // Store the public key in DER format before moving anything
  std::string publicKeyDer = publicKeyToDer(credKey);

  // Capture the rest of what a client needs while `credential` is still intact;
  // it is moved into PEM serialization below. Expiry is derived from the parent
  // certificate's notBefore plus valid_time, which is how the peer recomputes
  // it, rather than from the local clock.
  const uint32_t validTime = credential.valid_time;
  const uint16_t verifyScheme =
      static_cast<uint16_t>(credential.expected_verify_scheme);
  const auto expiresTimePoint =
      fizz::extensions::DelegatedCredentialUtils::getCredentialExpiresTime(
          parentCert->getX509(), credential);
  const uint64_t expiresAt = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          expiresTimePoint.time_since_epoch())
          .count());

  // Convert private key to PEM format before moving
  folly::ssl::BioUniquePtr bio(BIO_new(BIO_s_mem()));
  if (!bio) {
    throw std::runtime_error("Failed to create BIO");
  }

  EVP_PKEY* keyPtr = credKey.get();
  if (PEM_write_bio_PrivateKey(bio.get(), keyPtr, nullptr, nullptr, 0, nullptr,
                               nullptr) != 1) {
    throw std::runtime_error("Failed to write private key to BIO");
  }

  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio.get(), &mem);
  std::string keyPEM(mem->data, mem->length);

  // Generate PEM using Fizz's serialization (pass credential by move)
  std::string credentialPEM = fizz::extensions::generateDelegatedCredentialPEM(
      fizz::extensions::DelegatedCredentialMode::Server, std::move(credential),
      keyPEM);

  // Create ServiceCredential structure
  return std::pair{
      ServerCredential{static_cast<uint16_t>(credSigScheme), credentialPEM},
      ClientVerificationInfo{verifyScheme, publicKeyDer, validTime, expiresAt}};
}

}  // namespace sidecar
