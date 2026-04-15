#pragma once

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bsfchat::id {

struct Account {
    std::string id;
    std::string username;
    std::string email;
    std::string password_hash;
    std::string display_name;
    std::string avatar_url;
    bool is_admin = false;
    int64_t created_at = 0;
    int64_t updated_at = 0;
};

struct OAuthClient {
    std::string client_id;
    std::string client_secret;
    std::string name;
    std::string redirect_uris; // JSON array stored as text
    int64_t created_at = 0;
};

struct AuthCode {
    std::string code;
    std::string client_id;
    std::string account_id;
    std::string redirect_uri;
    std::string scope;
    std::string code_challenge;
    int64_t expires_at = 0;
};

struct RefreshToken {
    std::string token;
    std::string client_id;
    std::string account_id;
    std::string scope;
    int64_t expires_at = 0;
};

struct Session {
    std::string session_id;
    std::string account_id;
    int64_t created_at = 0;
    int64_t expires_at = 0;
};

class IdentityStore {
public:
    explicit IdentityStore(const std::string& db_path);
    ~IdentityStore();

    IdentityStore(const IdentityStore&) = delete;
    IdentityStore& operator=(const IdentityStore&) = delete;

    void initialize();

    // Accounts
    bool create_account(const Account& account);
    std::optional<Account> get_account_by_id(const std::string& id);
    std::optional<Account> get_account_by_username(const std::string& username);
    bool update_account(const Account& account);
    std::vector<Account> list_accounts(int limit = 100, int offset = 0);
    bool disable_account(const std::string& id);

    // OAuth clients
    bool create_oauth_client(const OAuthClient& client);
    std::optional<OAuthClient> get_oauth_client(const std::string& client_id);
    std::vector<OAuthClient> list_oauth_clients();

    // Auth codes
    bool store_auth_code(const AuthCode& code);
    std::optional<AuthCode> get_auth_code(const std::string& code);
    void delete_auth_code(const std::string& code);

    // Refresh tokens
    bool store_refresh_token(const RefreshToken& token);
    std::optional<RefreshToken> get_refresh_token(const std::string& token);
    void delete_refresh_token(const std::string& token);

    // Sessions
    bool create_session(const Session& session);
    std::optional<Session> get_session(const std::string& session_id);
    void delete_session(const std::string& session_id);
    void delete_expired_sessions();

private:
    void exec(const std::string& sql);
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

} // namespace bsfchat::id
