#include "crypto/KeyManager.h"
#include "core/Logger.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace bsfchat::id {

KeyManager::KeyManager(const std::string& keys_path) {
    load_or_generate(keys_path);
}

void KeyManager::load_or_generate(const std::string& keys_path) {
    namespace fs = std::filesystem;
    auto log = get_logger();

    fs::create_directories(keys_path);

    auto priv_path = fs::path(keys_path) / "private.pem";
    auto pub_path = fs::path(keys_path) / "public.pem";

    if (fs::exists(priv_path) && fs::exists(pub_path)) {
        log->info("Loading existing RSA keys from {}", keys_path);

        auto read_file = [](const fs::path& p) -> std::string {
            std::ifstream f(p);
            if (!f) throw std::runtime_error("Failed to read key file: " + p.string());
            std::ostringstream ss;
            ss << f.rdbuf();
            return ss.str();
        };

        private_key_pem_ = read_file(priv_path);
        public_key_pem_ = read_file(pub_path);
    } else {
        log->info("Generating new RSA keypair in {}", keys_path);

        auto [priv, pub] = bsfchat::generate_rsa_keypair();
        private_key_pem_ = priv;
        public_key_pem_ = pub;

        // Save keys to files
        {
            std::ofstream f(priv_path);
            if (!f) throw std::runtime_error("Failed to write private key");
            f << private_key_pem_;
        }
        {
            std::ofstream f(pub_path);
            if (!f) throw std::runtime_error("Failed to write public key");
            f << public_key_pem_;
        }

        log->info("RSA keypair generated and saved");
    }
}

std::string KeyManager::sign_token(const bsfchat::JwtClaims& claims) const {
    return bsfchat::jwt_sign(claims, private_key_pem_, key_id_);
}

nlohmann::json KeyManager::get_jwks() const {
    auto jwk = bsfchat::pem_to_jwk(public_key_pem_, key_id_);
    return nlohmann::json{{"keys", nlohmann::json::array({jwk})}};
}

} // namespace bsfchat::id
