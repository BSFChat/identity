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
    // Non-zero once an admin has disabled the account (security audit H1).
    // Disabling used to blank password_hash and nothing else; the flag is
    // what every credential lookup now checks, and it is reversible.
    int64_t disabled_at = 0;

    bool disabled() const { return disabled_at != 0; }
};

struct OAuthClient {
    std::string client_id;
    // Plaintext when handed to create_oauth_client(); the store keeps only
    // "sha256$<hex>" (crypto/Secrets.h), and that is what reads return. Empty
    // means a public client.
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
    // The bearer value on write and lookup; SHA-256 of it at rest, and in
    // anything read back from the store.
    std::string token;
    std::string client_id;
    std::string account_id;
    std::string scope;
    int64_t expires_at = 0;
    // Every token rotated out of one authorization-code grant shares a family
    // (security audit H4 / L4). The family is what the user sees and revokes
    // in the portal, what a replayed token kills, and what carries the
    // absolute expiry that rotation cannot extend.
    std::string family_id;
    int64_t family_expires_at = 0;
    int64_t created_at = 0;
    // Non-zero once this token has been exchanged for its successor. The row
    // is kept until it expires so a second presentation is recognised as a
    // replay rather than as an unknown token.
    int64_t replaced_at = 0;
};

enum class RotateResult {
    Rotated,  // old token retired, replacement stored
    Reused,   // old token had already been rotated: the family was revoked
    Invalid,  // unknown, expired, or its account is disabled
};

// Credential kinds stored in the `sessions` table. Browser session cookies and
// OIDC access tokens live in the same table but are NOT interchangeable: an
// access token minted for /userinfo must never authenticate the account portal.
namespace token_type {
inline constexpr const char* kBrowserSession = "session";
inline constexpr const char* kOidcAccess = "oidc_access";
} // namespace token_type

struct Session {
    // The bearer value on write and lookup. The table stores SHA-256 of it
    // (security audit L5), so rows read back carry the hash, not the token.
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
    // Marks the account disabled and, in the same transaction, deletes every
    // credential it holds: browser sessions, access tokens, refresh tokens,
    // pending auth codes, consent requests and 2FA login tokens. False when
    // the account does not exist.
    bool disable_account(const std::string& id);
    bool enable_account(const std::string& id);
    // Account id whose username_skeleton equals `skeleton`, if any.
    std::optional<std::string> find_account_by_username_skeleton(const std::string& skeleton);
    // True when another account (not `except_account_id`) already uses `email`.
    bool email_in_use(const std::string& email, const std::string& except_account_id = "");

    // Ends everything an account is signed in with except the browser session
    // `keep_session_id` (raw value; may be empty to keep nothing): sessions,
    // access tokens, refresh tokens, auth codes, consent requests and login
    // tokens. Returns the number of browser sessions and refresh-token
    // families ended. Used on password change, 2FA changes and "sign out
    // everywhere" (security audit H4).
    int revoke_account_credentials(const std::string& account_id,
                                   const std::string& keep_session_id = "");

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
    // Includes rotated-out rows (replaced_at != 0) so the caller can see a
    // replay; excludes tokens whose account is disabled.
    std::optional<RefreshToken> get_refresh_token(const std::string& token);
    void delete_refresh_token(const std::string& token);
    // Retires `old_token` and stores `replacement` in one transaction, so two
    // concurrent refreshes of one token cannot both succeed and fork it
    // (security audit L4). Presenting a token that was already rotated
    // revokes its whole family: one of the two presenters is not the client.
    RotateResult rotate_refresh_token(const std::string& old_token, const RefreshToken& replacement);
    // Deletes the family `token` belongs to (RFC 7009 revocation).
    void revoke_refresh_token_family(const std::string& token);
    // The live token of each family, newest first.
    std::vector<RefreshToken> list_refresh_tokens_for_account(const std::string& account_id);
    bool delete_refresh_family(const std::string& account_id, const std::string& family_id);

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
    // Deletes by the value stored in the table (the hash, as returned by
    // list_sessions_for_account), scoped to the owning account.
    bool delete_stored_session(const std::string& account_id, const std::string& stored_id);
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
    // Records `step` as the account's last accepted TOTP time-step, only if
    // it is later than the one already recorded. False means the step (or a
    // later one) was already used: the code is a replay (security audit M2).
    bool accept_totp_step(const std::string& account_id, uint64_t step);
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
    int revoke_credentials_locked(const std::string& account_id, const std::string& keep_hash);

    sqlite3* db_ = nullptr;
    std::mutex mutex_;
};

} // namespace bsfchat::id
