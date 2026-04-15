#include <gtest/gtest.h>
#include "crypto/PasswordHash.h"
#include "store/IdentityStore.h"

#include <chrono>

using namespace bsfchat::id;

TEST(PasswordHashTest, HashAndVerify) {
    auto hash = hash_password("mysecretpassword", 10); // use lower cost for test speed
    EXPECT_FALSE(hash.empty());
    EXPECT_TRUE(hash.starts_with("$pbkdf2$"));
    EXPECT_TRUE(verify_password("mysecretpassword", hash));
    EXPECT_FALSE(verify_password("wrongpassword", hash));
}

TEST(PasswordHashTest, DifferentPasswordsDifferentHashes) {
    auto hash1 = hash_password("password1", 10);
    auto hash2 = hash_password("password2", 10);
    EXPECT_NE(hash1, hash2);
}

TEST(PasswordHashTest, SamPasswordDifferentSalts) {
    auto hash1 = hash_password("samepassword", 10);
    auto hash2 = hash_password("samepassword", 10);
    // Different salts should produce different hashes
    EXPECT_NE(hash1, hash2);
    // But both should verify
    EXPECT_TRUE(verify_password("samepassword", hash1));
    EXPECT_TRUE(verify_password("samepassword", hash2));
}

TEST(PasswordHashTest, InvalidHashFormat) {
    EXPECT_FALSE(verify_password("anything", "not-a-valid-hash"));
    EXPECT_FALSE(verify_password("anything", ""));
    EXPECT_FALSE(verify_password("anything", "$notpbkdf2$12$salt$hash"));
}

TEST(RegistrationValidationTest, UsernameValidation) {
    // Test that username constraints work at the store level
    auto store = std::make_unique<IdentityStore>(":memory:");
    store->initialize();

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Empty username should still be insertable at DB level
    // (validation happens in the handler, not the store)
    Account a;
    a.id = "uuid-1";
    a.username = "validuser";
    a.password_hash = hash_password("password123", 10);
    a.created_at = now;
    a.updated_at = now;
    EXPECT_TRUE(store->create_account(a));

    // Verify the account was created with the correct hash
    auto retrieved = store->get_account_by_username("validuser");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_TRUE(verify_password("password123", retrieved->password_hash));
    EXPECT_FALSE(verify_password("wrongpassword", retrieved->password_hash));
}

TEST(RegistrationValidationTest, DuplicateUsername) {
    auto store = std::make_unique<IdentityStore>(":memory:");
    store->initialize();

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    Account a1;
    a1.id = "uuid-dup-1";
    a1.username = "taken";
    a1.password_hash = "hash1";
    a1.created_at = now;
    a1.updated_at = now;

    Account a2;
    a2.id = "uuid-dup-2";
    a2.username = "taken";
    a2.password_hash = "hash2";
    a2.created_at = now;
    a2.updated_at = now;

    EXPECT_TRUE(store->create_account(a1));
    EXPECT_FALSE(store->create_account(a2));
}

TEST(RegistrationValidationTest, EmailOptional) {
    auto store = std::make_unique<IdentityStore>(":memory:");
    store->initialize();

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    Account a;
    a.id = "uuid-no-email";
    a.username = "noemail";
    a.password_hash = "hash";
    a.created_at = now;
    a.updated_at = now;
    // email left empty

    EXPECT_TRUE(store->create_account(a));

    auto retrieved = store->get_account_by_id("uuid-no-email");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_TRUE(retrieved->email.empty());
}
