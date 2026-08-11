#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include "credential.h"
#include "files.h"
#include "nlohmann/json.hpp"

int main(int argc, char* argv[]) {
  // Read certificate and key
  folly::ssl::X509UniquePtr certificate = sidecar::loadCertificate("fizz.crt");
  folly::ssl::EvpPkeyUniquePtr key = sidecar::loadPrivateKey("fizz.key");

  // Verify the certificate has delegated credential extension
  fizz::extensions::DelegatedCredentialUtils::checkExtensions(certificate);

  // Create certificate vector for OpenSSLSelfCertImpl
  std::vector<folly::ssl::X509UniquePtr> certChain;
  certChain.push_back(std::move(certificate));

  // Create parent certificate object
  auto parentCertificate = std::make_shared<
      fizz::openssl::OpenSSLSelfCertImpl<fizz::openssl::KeyType::P256>>(
      std::move(key), std::move(certChain));

  // Load key again.
  key = sidecar::loadPrivateKey("fizz.key");

  // How long to make the delegation valid for.
  std::chrono::seconds validitySeconds = std::chrono::hours(24 * 7);

  // Generate delegated credential
  auto [serverCredential, clientVerificationInfo] =
      sidecar::generateDelegatedCredential(std::move(parentCertificate),
                                           std::move(key), validitySeconds);

  // serialize server.
  nlohmann::json serverJson = nlohmann::json::object(
      {{"signatureScheme", serverCredential.signatureScheme},
       {"credentialPEM", serverCredential.credentialPEM}});

  std::ofstream server_file("/tmp/fizz_server.json");
  server_file << serverJson.dump(2) << std::endl;
  server_file.close();

  // Serialize client. service_name stays empty because the peer ignores it;
  // valid_time and expires_at must be the credential's real values, since the
  // peer compares both against the credential it is offered.
  nlohmann::json clientJson = nlohmann::json::object(
      {{"service_name", ""},
       {"valid_time", clientVerificationInfo.validTime},
       {"expected_verify_scheme", clientVerificationInfo.verifyScheme},
       {"public_key_der", clientVerificationInfo.publicKeyDer},
       {"expires_at", clientVerificationInfo.expiresAt}});

  std::ofstream client_file("/tmp/fizz_client.json");
  client_file << clientJson.dump(2) << std::endl;
  client_file.close();

  return 0;
}
