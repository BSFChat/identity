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
    // Canonical URL of the chat server the grant is for (RFC 8707 `resource`),
    // or empty for a request that named none. Becomes the id_token's `aud`.
    std::string resource;
    // OIDC nonce from the authorization request, echoed into the id_token.
    std::string nonce;
};

struct RefreshToken {
    std::string token;
    std::string client_id;
    std::string account_id;
    std::string scope;
    int64_t expires_at = 0;
};

// Credential kinds stored in the `sessions` table. Browser session cookies and
// OIDC access tokens live in the same table but are NOT interchangeable: an
// access token minted for /userinfo must never authenticate the account portal.
namespace token_type {
inline constexpr const char* kBrowserSession = "session";
inline constexpr const char* kOidcAccess = "oidc_access";
} // namespace token_type

struct Session {
    std::string session_id;
    std::string account_id;
    int64_t created_at = 0;
    int64_t expires_at = 0;
    // Which credential kind this row is. Defaults to a browser session so that
    // any caller that forgets to set it gets the more restricted OIDC checks
    // failing closed rather than the portal checks passing open.
    std::string token_type = token_type::kBrowserSession;
    // OAuth scope granted to this credential. Empty for browser sessions,
    // which are not scope-limited.
    std::string scope;
    // Issuing OAuth client, for OIDC access tokens only.
    std::string client_id;
};

// A pending user-facing consent decision for an authorization request.
struct ConsentRequest {
    std::string token;
    std::string session_id;   // browser session the request is bound to
    std::string account_id;
    std::string client_id;
    std::string redirect_uri;
    std::string scope;
    std::string state;
    std::string code_challenge;
    int64_t expires_at = 0;
    std::string resource;     // see AuthCode::resource
    std::string nonce;
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
    bool update_password_hash(const std::string& id, const std::string& password_hash);
    std::vector<Account> list_accounts(int limit = 100, int offset = 0);
    bool disable_account(const std::string& id);

    // OAuth clients
    bool create_oauth_client(const OAuthClient& client);
    std::optional<OAuthClient> get_oauth_client(const std::string& client_id);
    std::vector<OAuthClient> list_oauth_clients();
    bool update_oauth_client_redirect_uris(const std::string& client_id, const std::string& redirect_uris_json);

    // Auth codes
    bool store_auth_code(const AuthCode& code);
    std::optional<AuthCode> get_auth_code(const std::string& code);
    void delete_auth_code(const std::string& code);
    // Atomically fetches and deletes an authorization code inside a single
    // transaction, so two concurrent redemptions cannot both succeed.
    std::optional<AuthCode> consume_auth_code(const std::string& code);
    void delete_expired_auth_codes();

    // Refresh tokens
    bool store_refresh_token(const RefreshToken& token);
    std::optional<RefreshToken> get_refresh_token(const std::string& token);
    void delete_refresh_token(const std::string& token);

    // Sessions / access tokens
    bool create_session(const Session& session);
    // Unfiltered lookup. Prefer the typed accessors below in request handlers:
    // they filter in SQL and therefore cannot be misused by forgetting a check.
    std::optional<Session> get_session(const std::string& session_id);
    // Browser session cookies only — the credential the account portal trusts.
    std::optional<Session> get_browser_session(const std::string& session_id);
    // OIDC access tokens only — never valid as a portal credential.
    std::optional<Session> get_oidc_access_token(const std::string& token);
    void delete_session(const std::string& session_id);
    void delete_expired_sessions();
    // Browser sessions only; access tokens are not user-visible "sessions".
    std::vector<Session> list_sessions_for_account(const std::string& account_id);

    // TOTP
    // `backup_codes` are the plaintext codes shown to the user once; they are
    // hashed before being written and are not recoverable from the database.
    void set_totp_secret(const std::string& account_id, const std::string& secret,
                         const std::vector<std::string>& backup_codes);
    std::optional<TotpInfo> get_totp(const std::string& account_id);
    void enable_totp(const std::string& account_id);
    void disable_totp(const std::string& account_id);
    // Verifies and consumes a single backup code atomically (one transaction),
    // so the same code cannot be redeemed twice by concurrent requests.
    bool consume_backup_code(const std::string& account_id, const std::string& code);

    // Login tokens (temporary 5min tokens for 2FA flow)
    void create_login_token(const std::string& token, const std::string& account_id, int64_t expires_at);
    std::optional<std::string> validate_login_token(const std::string& token);
    void delete_login_token(const std::string& token);
    // Increments the failure counter for a login token and destroys the token
    // once max_attempts is reached. Returns true when the token was destroyed.
    bool record_login_token_failure(const std::string& token, int max_attempts);
    void delete_expired_login_tokens();

    // Consent requests (bound to a browser session, single use).
    // The row is deleted only when `session_id` matches the session the prompt
    // was issued to, so a rejected (e.g. cross-site) decision cannot burn a
    // pending request belonging to a legitimate user.
    bool store_consent_request(const ConsentRequest& request);
    std::optional<ConsentRequest> consume_consent_request(const std::string& token,
                                                          const std::string& session_id);
    void delete_expired_consent_requests();

    // Refresh token housekeeping
    void delete_expired_refresh_tokens();

    // Runs every expiry sweep in one call. Safe to call periodically.
    void sweep_expired();

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
    // Applies pending schema migrations. Driven by PRAGMA user_version, with a
    // belt-and-braces column-existence check so a stale version cannot brick an
    // install. Must be called with mutex_ held.
    void migrate_locked();
    bool has_column_locked(const std::string& table, const std::string& column);

    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

} // namespace bsfchat::id
