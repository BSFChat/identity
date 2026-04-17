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

struct TotpInfo {
    std::string secret;
    bool enabled = false;
    std::string backup_codes_json;
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
    std::vector<Session> list_sessions_for_account(const std::string& account_id);

    // TOTP
    void set_totp_secret(const std::string& account_id, const std::string& secret, const std::string& backup_codes_json);
    std::optional<TotpInfo> get_totp(const std::string& account_id);
    void enable_totp(const std::string& account_id);
    void disable_totp(const std::string& account_id);
    bool consume_backup_code(const std::string& account_id, const std::string& code);

    // Login tokens (temporary 5min tokens for 2FA flow)
    void create_login_token(const std::string& token, const std::string& account_id, int64_t expires_at);
    std::optional<std::string> validate_login_token(const std::string& token);
    void delete_login_token(const std::string& token);

    // Server memberships — tracks which BSFChat servers a user has joined
    // so the client can restore all connections from a single identity login.
    struct ServerMembership {
        std::string id;
        std::string server_url;
        std::string server_name; // human-readable, optional
        int64_t joined_at = 0;
    };
    void add_server_membership(const std::string& account_id, const std::string& server_url,
                                const std::string& server_name = "");
    void remove_server_membership(const std::string& account_id, const std::string& server_url);
    std::vector<ServerMembership> list_server_memberships(const std::string& account_id);

private:
    void exec(const std::string& sql);
    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

} // namespace bsfchat::id
