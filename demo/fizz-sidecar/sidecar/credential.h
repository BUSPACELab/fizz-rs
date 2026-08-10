#ifndef SIDECAR_CREDENTIAL_H_
#define SIDECAR_CREDENTIAL_H_

#include <chrono>
#include <memory>
#include <string>
#include <utility>

#include "fizz/backend/openssl/certificate/CertUtils.h"
#include "fizz/backend/openssl/certificate/OpenSSLSelfCertImpl.h"
#include "fizz/crypto/Utils.h"
#include "fizz/extensions/delegatedcred/DelegatedCredentialUtils.h"
#include "fizz/extensions/delegatedcred/Serialization.h"
#include "fizz/protocol/CertificateVerifier.h"

namespace sidecar {

// What the server needs.
struct ServerCredential {
  uint16_t signatureScheme;
  std::string credentialPEM;
};

// What the client needs.
struct ClientVerificationInfo {
  uint16_t verifyScheme;
  std::string publicKeyDer;
  // A client compares both of these against the credential it is offered, so
  // they have to be the credential's real values rather than placeholders.
  uint32_t validTime;
  uint64_t expiresAt;
};

// Generate a delegated credential.
std::pair<ServerCredential, ClientVerificationInfo> generateDelegatedCredential(
    std::shared_ptr<fizz::SelfCert> parentCert,
    folly::ssl::EvpPkeyUniquePtr parentKey,
    std::chrono::seconds validitySeconds);

}  // namespace sidecar

#endif  // SIDECAR_CREDENTIAL_H_
