#include <gtest/gtest.h>
#include "store/IdentityStore.h"

#include <chrono>

using namespace bsfchat::id;

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

class IdentityStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        store = std::make_unique<IdentityStore>(":memory:");
        store->initialize();
    }

    std::unique_ptr<IdentityStore> store;
};

TEST_F(IdentityStoreTest, CreateAndGetAccount) {
    auto now = now_seconds();
    Account account;
    account.id = "test-uuid-1234";
    account.username = "alice";
    account.email = "alice@example.com";
    account.password_hash = "$pbkdf2$12$aabbccdd$eeff0011";
    account.display_name = "Alice";
    account.created_at = now;
    account.updated_at = now;

    ASSERT_TRUE(store->create_account(account));

    auto retrieved = store->get_account_by_id("test-uuid-1234");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->username, "alice");
    EXPECT_EQ(retrieved->email, "alice@example.com");
    EXPECT_EQ(retrieved->display_name, "Alice");
    EXPECT_FALSE(retrieved->is_admin);
}

TEST_F(IdentityStoreTest, GetAccountByUsername) {
    auto now = now_seconds();
    Account account;
    account.id = "test-uuid-5678";
    account.username = "bob";
    account.password_hash = "hash";
    account.display_name = "Bob";
    account.created_at = now;
    account.updated_at = now;

    ASSERT_TRUE(store->create_account(account));

    auto retrieved = store->get_account_by_username("bob");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->id, "test-uuid-5678");
}

TEST_F(IdentityStoreTest, DuplicateUsernameRejected) {
    auto now = now_seconds();
    Account a1;
    a1.id = "uuid-1";
    a1.username = "charlie";
    a1.password_hash = "hash";
    a1.created_at = now;
    a1.updated_at = now;

    Account a2;
    a2.id = "uuid-2";
    a2.username = "charlie";
    a2.password_hash = "hash2";
    a2.created_at = now;
    a2.updated_at = now;

    ASSERT_TRUE(store->create_account(a1));
    ASSERT_FALSE(store->create_account(a2));
}

TEST_F(IdentityStoreTest, UpdateAccount) {
    auto now = now_seconds();
    Account account;
    account.id = "uuid-update";
    account.username = "dave";
    account.password_hash = "hash";
    account.display_name = "Dave";
    account.created_at = now;
    account.updated_at = now;

    ASSERT_TRUE(store->create_account(account));

    account.display_name = "David";
    account.email = "dave@example.com";
    account.updated_at = now + 10;
    ASSERT_TRUE(store->update_account(account));

    auto retrieved = store->get_account_by_id("uuid-update");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->display_name, "David");
    EXPECT_EQ(retrieved->email, "dave@example.com");
}

TEST_F(IdentityStoreTest, ListAccounts) {
    auto now = now_seconds();
    for (int i = 0; i < 5; ++i) {
        Account a;
        a.id = "uuid-list-" + std::to_string(i);
        a.username = "user" + std::to_string(i);
        a.password_hash = "hash";
        a.created_at = now + i;
        a.updated_at = now + i;
        store->create_account(a);
    }

    auto accounts = store->list_accounts(10, 0);
    EXPECT_EQ(accounts.size(), 5u);
}

TEST_F(IdentityStoreTest, AuthCodeFlow) {
    auto now = now_seconds();

    AuthCode code;
    code.code = "authcode123";
    code.client_id = "client1";
    code.account_id = "account1";
    code.redirect_uri = "http://localhost/callback";
    code.scope = "openid profile";
    code.expires_at = now + 300;

    ASSERT_TRUE(store->store_auth_code(code));

    auto retrieved = store->get_auth_code("authcode123");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->client_id, "client1");
    EXPECT_EQ(retrieved->account_id, "account1");
    EXPECT_EQ(retrieved->redirect_uri, "http://localhost/callback");
    EXPECT_EQ(retrieved->scope, "openid profile");

    store->delete_auth_code("authcode123");
    EXPECT_FALSE(store->get_auth_code("authcode123").has_value());
}

TEST_F(IdentityStoreTest, RefreshTokenCRUD) {
    auto now = now_seconds();

    RefreshToken rt;
    rt.token = "refresh123";
    rt.client_id = "client1";
    rt.account_id = "account1";
    rt.scope = "openid";
    rt.expires_at = now + 86400 * 30;

    ASSERT_TRUE(store->store_refresh_token(rt));

    auto retrieved = store->get_refresh_token("refresh123");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->client_id, "client1");

    store->delete_refresh_token("refresh123");
    EXPECT_FALSE(store->get_refresh_token("refresh123").has_value());
}

TEST_F(IdentityStoreTest, SessionCRUD) {
    auto now = now_seconds();

    // Create an account first (foreign key constraint)
    Account account;
    account.id = "account1";
    account.username = "sessionuser";
    account.password_hash = "hash";
    account.created_at = now;
    account.updated_at = now;
    ASSERT_TRUE(store->create_account(account));

    Session session;
    session.session_id = "session123";
    session.account_id = "account1";
    session.created_at = now;
    session.expires_at = now + 3600;

    ASSERT_TRUE(store->create_session(session));

    auto retrieved = store->get_session("session123");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->account_id, "account1");

    store->delete_session("session123");
    EXPECT_FALSE(store->get_session("session123").has_value());
}

TEST_F(IdentityStoreTest, OAuthClientCRUD) {
    auto now = now_seconds();

    OAuthClient client;
    client.client_id = "client-abc";
    client.client_secret = "secret-xyz";
    client.name = "Test App";
    client.redirect_uris = R"(["http://localhost/callback"])";
    client.created_at = now;

    ASSERT_TRUE(store->create_oauth_client(client));

    auto retrieved = store->get_oauth_client("client-abc");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->name, "Test App");
    EXPECT_EQ(retrieved->client_secret, "secret-xyz");

    auto clients = store->list_oauth_clients();
    EXPECT_EQ(clients.size(), 1u);
}

TEST_F(IdentityStoreTest, DisableAccount) {
    auto now = now_seconds();
    Account account;
    account.id = "uuid-disable";
    account.username = "disableme";
    account.password_hash = "secrethash";
    account.created_at = now;
    account.updated_at = now;

    ASSERT_TRUE(store->create_account(account));
    ASSERT_TRUE(store->disable_account("uuid-disable"));

    auto retrieved = store->get_account_by_id("uuid-disable");
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_TRUE(retrieved->password_hash.empty());
}
