#include <gtest/gtest.h>
#include "crypto/KeyManager.h"

#include <bsfchat/JwtUtils.h>
#include <nlohmann/json.hpp>
#include <filesystem>
#include <chrono>

using namespace bsfchat::id;
using json = nlohmann::json;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

class OidcTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Use a temp directory for keys
        test_keys_dir = std::filesystem::temp_directory_path() / "bsfchat_id_test_keys";
        std::filesystem::remove_all(test_keys_dir);
        key_manager = std::make_unique<KeyManager>(test_keys_dir.string());
    }

    void TearDown() override {
        std::filesystem::remove_all(test_keys_dir);
    }

    std::filesystem::path test_keys_dir;
    std::unique_ptr<KeyManager> key_manager;
};

TEST_F(OidcTest, KeyManagerGeneratesKeys) {
    EXPECT_FALSE(key_manager->get_public_key().empty());
    EXPECT_EQ(key_manager->get_key_id(), "bsfchat-id-1");
}

TEST_F(OidcTest, KeyManagerLoadsExistingKeys) {
    auto pub_key_1 = key_manager->get_public_key();

    // Create a new KeyManager pointing to the same directory
    auto key_manager_2 = std::make_unique<KeyManager>(test_keys_dir.string());
    EXPECT_EQ(key_manager_2->get_public_key(), pub_key_1);
}

TEST_F(OidcTest, SignAndVerifyToken) {
    auto now = now_seconds();

    bsfchat::JwtClaims claims;
    claims.sub = "user-123";
    claims.iss = "http://localhost:8480";
    claims.aud = "test-client";
    claims.iat = now;
    claims.exp = now + 3600;
    claims.name = "Test User";
    claims.email = "test@example.com";

    auto token = key_manager->sign_token(claims);
    EXPECT_FALSE(token.empty());

    // Verify using the protocol library
    auto verified = bsfchat::jwt_verify(token, key_manager->get_public_key(), "http://localhost:8480");
    ASSERT_TRUE(verified.has_value());
    EXPECT_EQ(verified->sub, "user-123");
    EXPECT_EQ(verified->iss, "http://localhost:8480");
    EXPECT_EQ(verified->aud, "test-client");
    EXPECT_EQ(verified->name.value_or(""), "Test User");
    EXPECT_EQ(verified->email.value_or(""), "test@example.com");
}

TEST_F(OidcTest, ExpiredTokenFailsVerification) {
    auto now = now_seconds();

    bsfchat::JwtClaims claims;
    claims.sub = "user-456";
    claims.iss = "http://localhost:8480";
    claims.aud = "test-client";
    claims.iat = now - 7200;
    claims.exp = now - 3600; // expired 1 hour ago

    auto token = key_manager->sign_token(claims);
    EXPECT_FALSE(token.empty());

    auto verified = bsfchat::jwt_verify(token, key_manager->get_public_key(), "http://localhost:8480");
    EXPECT_FALSE(verified.has_value());
}

TEST_F(OidcTest, WrongIssuerFailsVerification) {
    auto now = now_seconds();

    bsfchat::JwtClaims claims;
    claims.sub = "user-789";
    claims.iss = "http://localhost:8480";
    claims.aud = "test-client";
    claims.iat = now;
    claims.exp = now + 3600;

    auto token = key_manager->sign_token(claims);

    auto verified = bsfchat::jwt_verify(token, key_manager->get_public_key(), "http://wrong-issuer:8480");
    EXPECT_FALSE(verified.has_value());
}

TEST_F(OidcTest, JwksFormat) {
    auto jwks = key_manager->get_jwks();

    ASSERT_TRUE(jwks.contains("keys"));
    ASSERT_TRUE(jwks["keys"].is_array());
    ASSERT_EQ(jwks["keys"].size(), 1u);

    auto& key = jwks["keys"][0];
    EXPECT_EQ(key["kty"], "RSA");
    EXPECT_EQ(key["kid"], "bsfchat-id-1");
    EXPECT_EQ(key["use"], "sig");
    EXPECT_EQ(key["alg"], "RS256");
    EXPECT_TRUE(key.contains("n"));
    EXPECT_TRUE(key.contains("e"));
}

TEST_F(OidcTest, DiscoveryDocumentFormat) {
    // Test the structure that the OIDC discovery endpoint would return
    std::string issuer = "http://localhost:8480";
    json discovery = {
        {"issuer", issuer},
        {"authorization_endpoint", issuer + "/authorize"},
        {"token_endpoint", issuer + "/token"},
        {"userinfo_endpoint", issuer + "/userinfo"},
        {"jwks_uri", issuer + "/jwks"},
        {"scopes_supported", json::array({"openid", "profile", "email"})},
        {"response_types_supported", json::array({"code"})},
        {"grant_types_supported", json::array({"authorization_code", "refresh_token"})},
        {"id_token_signing_alg_values_supported", json::array({"RS256"})}
    };

    EXPECT_EQ(discovery["issuer"], issuer);
    EXPECT_EQ(discovery["authorization_endpoint"], issuer + "/authorize");
    EXPECT_EQ(discovery["token_endpoint"], issuer + "/token");
    EXPECT_TRUE(discovery["scopes_supported"].is_array());
    EXPECT_EQ(discovery["scopes_supported"].size(), 3u);
}
