#pragma once

#include <bsfchat/JwtUtils.h>
#include <nlohmann/json.hpp>
#include <string>

namespace bsfchat::id {

class KeyManager {
public:
    // Initialize key manager with path to keys directory.
    // Generates new RSA keypair on first run, loads existing on subsequent runs.
    explicit KeyManager(const std::string& keys_path);

    // Sign JWT claims and return the encoded token string.
    std::string sign_token(const bsfchat::JwtClaims& claims) const;

    // Get the JWKS (JSON Web Key Set) for the public key.
    nlohmann::json get_jwks() const;

    // Get the public key in PEM format.
    const std::string& get_public_key() const { return public_key_pem_; }

    // Get the key ID used for signing.
    const std::string& get_key_id() const { return key_id_; }

private:
    void load_or_generate(const std::string& keys_path);

    std::string private_key_pem_;
    std::string public_key_pem_;
    std::string key_id_ = "bsfchat-id-1";
};

} // namespace bsfchat::id
