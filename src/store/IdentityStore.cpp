#include "store/IdentityStore.h"
#include "core/Logger.h"
#include "core/WebUtil.h"
#include "crypto/PasswordHash.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace bsfchat::id {

namespace {

// Bump when a new migration step is appended to migrate_locked().
constexpr int kSchemaVersion = 1;

// Backup codes carry ~47 bits of entropy and are checked one at a time against
// at most a handful of stored hashes, so a lighter KDF than the password one is
// appropriate; this keeps a redemption well under a second.
constexpr int kBackupCodeIterations = 100000;

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

StmtPtr prepare(sqlite3* db, const std::string& sql) {
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error(std::string("SQL prepare error: ") + sqlite3_errmsg(db) + " [" + sql + "]");
    }
    return StmtPtr(stmt);
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto ptr = sqlite3_column_text(stmt, col);
    return ptr ? reinterpret_cast<const char*>(ptr) : "";
}

void bind_text(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT);
}

// RAII wrapper for a transaction. Rolls back if commit() is never called, so an
// exception thrown mid-way cannot leave a half-applied read-modify-write.
class Transaction {
public:
    explicit Transaction(sqlite3* db) : db_(db) {
        sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
    }
    ~Transaction() {
        if (!done_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
    }
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;

    void commit() {
        if (!done_) {
            sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr);
            done_ = true;
        }
    }

private:
    sqlite3* db_;
    bool done_ = false;
};

} // namespace

IdentityStore::IdentityStore(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error(std::string("Failed to open database: ") + sqlite3_errmsg(db_));
    }
    exec("PRAGMA journal_mode=WAL");
    exec("PRAGMA foreign_keys=ON");
    exec("PRAGMA busy_timeout=5000");
}

IdentityStore::~IdentityStore() {
    if (db_) sqlite3_close(db_);
}

void IdentityStore::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQL exec error: " + msg);
    }
}

void IdentityStore::initialize() {
    std::lock_guard lock(mutex_);

    exec(R"(
        CREATE TABLE IF NOT EXISTS accounts (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT,
            display_name TEXT,
            avatar_url TEXT,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS sso_links (
            account_id TEXT REFERENCES accounts(id),
            provider TEXT NOT NULL,
            provider_sub TEXT NOT NULL,
            email TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (account_id, provider)
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_secret TEXT NOT NULL,
            name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            code_challenge TEXT,
            expires_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            scope TEXT,
            expires_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            account_id TEXT NOT NULL REFERENCES accounts(id),
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS user_totp (
            account_id TEXT PRIMARY KEY REFERENCES accounts(id),
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            backup_codes TEXT,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS login_tokens (
            token TEXT PRIMARY KEY,
            account_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL
        )
    )");

    exec(R"(
        CREATE TABLE IF NOT EXISTS server_memberships (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id  TEXT NOT NULL REFERENCES accounts(id),
            server_url  TEXT NOT NULL,
            server_name TEXT NOT NULL DEFAULT '',
            joined_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            UNIQUE(account_id, server_url)
        )
    )");

    // Pending consent decisions for /authorize. Bound to the browser session
    // that was shown the prompt, which is what stops a third-party page from
    // driving the grant.
    exec(R"(
        CREATE TABLE IF NOT EXISTS consent_requests (
            token          TEXT PRIMARY KEY,
            session_id     TEXT NOT NULL,
            account_id     TEXT NOT NULL,
            client_id      TEXT NOT NULL,
            redirect_uri   TEXT NOT NULL,
            scope          TEXT NOT NULL DEFAULT '',
            state          TEXT NOT NULL DEFAULT '',
            code_challenge TEXT NOT NULL DEFAULT '',
            expires_at     INTEGER NOT NULL
        )
    )");

    exec("CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username)");
    exec("CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id)");
    exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_account ON refresh_tokens(account_id)");
    exec("CREATE INDEX IF NOT EXISTS idx_server_memberships_account ON server_memberships(account_id)");

    migrate_locked();
}

bool IdentityStore::has_column_locked(const std::string& table, const std::string& column) {
    auto stmt = prepare(db_, "SELECT 1 FROM pragma_table_info(?) WHERE name = ?");
    bind_text(stmt.get(), 1, table);
    bind_text(stmt.get(), 2, column);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
}

void IdentityStore::migrate_locked() {
    auto log = get_logger();

    int version = 0;
    {
        auto stmt = prepare(db_, "PRAGMA user_version");
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            version = sqlite3_column_int(stmt.get(), 0);
        }
    }

    // Every step is written to be idempotent (guarded by has_column_locked)
    // so that a database whose user_version was lost or never set still
    // converges instead of throwing from prepare() on a missing column.

    // --- v1: separate credential kinds, and count 2FA attempts -------------
    if (version < kSchemaVersion) {
        if (!has_column_locked("sessions", "token_type")) {
            exec("ALTER TABLE sessions ADD COLUMN token_type TEXT NOT NULL DEFAULT 'session'");
            // Pre-existing rows are indistinguishable by name, but not by
            // lifetime: OIDC access tokens were always created with a 1 hour
            // TTL, browser sessions with 7 days. Reclassify accordingly so the
            // previously issued access tokens lose portal privileges too.
            exec("UPDATE sessions SET token_type = 'oidc_access' "
                 "WHERE expires_at - created_at <= 3600");
            log->info("Schema migration: classified existing sessions by credential type");
        }
        if (!has_column_locked("sessions", "scope")) {
            exec("ALTER TABLE sessions ADD COLUMN scope TEXT NOT NULL DEFAULT ''");
        }
        if (!has_column_locked("sessions", "client_id")) {
            exec("ALTER TABLE sessions ADD COLUMN client_id TEXT NOT NULL DEFAULT ''");
        }
        if (!has_column_locked("login_tokens", "attempts")) {
            exec("ALTER TABLE login_tokens ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0");
        }

        exec("CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(token_type)");

        // Hash any backup codes still stored in plaintext.
        std::vector<std::pair<std::string, std::string>> to_rehash;
        {
            auto stmt = prepare(db_, "SELECT account_id, backup_codes FROM user_totp");
            while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                to_rehash.emplace_back(col_text(stmt.get(), 0), col_text(stmt.get(), 1));
            }
        }
        for (const auto& [account_id, codes_json] : to_rehash) {
            nlohmann::json codes = nlohmann::json::parse(codes_json, nullptr, false);
            if (codes.is_discarded() || !codes.is_array()) continue;

            bool changed = false;
            nlohmann::json hashed = nlohmann::json::array();
            for (const auto& entry : codes) {
                if (!entry.is_string()) continue;
                auto value = entry.get<std::string>();
                if (value.rfind("$pbkdf2", 0) == 0) {
                    hashed.push_back(value); // already hashed
                } else {
                    hashed.push_back(hash_password(value, kBackupCodeIterations));
                    changed = true;
                }
            }
            if (!changed) continue;

            auto upd = prepare(db_, "UPDATE user_totp SET backup_codes = ? WHERE account_id = ?");
            bind_text(upd.get(), 1, hashed.dump());
            bind_text(upd.get(), 2, account_id);
            sqlite3_step(upd.get());
            log->info("Schema migration: hashed backup codes for account {}", account_id);
        }

        exec("PRAGMA user_version = " + std::to_string(kSchemaVersion));
        log->info("Identity database schema migrated to version {}", kSchemaVersion);
    }
}

// Accounts

bool IdentityStore::create_account(const Account& account) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO accounts (id, username, email, password_hash, display_name, avatar_url, is_admin, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, account.id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, account.username.c_str(), -1, SQLITE_TRANSIENT);
    if (account.email.empty()) {
        sqlite3_bind_null(stmt.get(), 3);
    } else {
        sqlite3_bind_text(stmt.get(), 3, account.email.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt.get(), 4, account.password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, account.display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, account.avatar_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt.get(), 7, account.is_admin ? 1 : 0);
    sqlite3_bind_int64(stmt.get(), 8, account.created_at);
    sqlite3_bind_int64(stmt.get(), 9, account.updated_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<Account> IdentityStore::get_account_by_id(const std::string& id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT id, username, email, password_hash, display_name, avatar_url, is_admin, created_at, updated_at "
        "FROM accounts WHERE id = ?");
    sqlite3_bind_text(stmt.get(), 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        Account a;
        a.id = col_text(stmt.get(), 0);
        a.username = col_text(stmt.get(), 1);
        a.email = col_text(stmt.get(), 2);
        a.password_hash = col_text(stmt.get(), 3);
        a.display_name = col_text(stmt.get(), 4);
        a.avatar_url = col_text(stmt.get(), 5);
        a.is_admin = sqlite3_column_int(stmt.get(), 6) != 0;
        a.created_at = sqlite3_column_int64(stmt.get(), 7);
        a.updated_at = sqlite3_column_int64(stmt.get(), 8);
        return a;
    }
    return std::nullopt;
}

std::optional<Account> IdentityStore::get_account_by_username(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT id, username, email, password_hash, display_name, avatar_url, is_admin, created_at, updated_at "
        "FROM accounts WHERE username = ?");
    sqlite3_bind_text(stmt.get(), 1, username.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        Account a;
        a.id = col_text(stmt.get(), 0);
        a.username = col_text(stmt.get(), 1);
        a.email = col_text(stmt.get(), 2);
        a.password_hash = col_text(stmt.get(), 3);
        a.display_name = col_text(stmt.get(), 4);
        a.avatar_url = col_text(stmt.get(), 5);
        a.is_admin = sqlite3_column_int(stmt.get(), 6) != 0;
        a.created_at = sqlite3_column_int64(stmt.get(), 7);
        a.updated_at = sqlite3_column_int64(stmt.get(), 8);
        return a;
    }
    return std::nullopt;
}

bool IdentityStore::update_account(const Account& account) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "UPDATE accounts SET display_name = ?, avatar_url = ?, email = ?, updated_at = ? WHERE id = ?");
    sqlite3_bind_text(stmt.get(), 1, account.display_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, account.avatar_url.c_str(), -1, SQLITE_TRANSIENT);
    if (account.email.empty()) {
        sqlite3_bind_null(stmt.get(), 3);
    } else {
        sqlite3_bind_text(stmt.get(), 3, account.email.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_int64(stmt.get(), 4, account.updated_at);
    sqlite3_bind_text(stmt.get(), 5, account.id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool IdentityStore::update_password_hash(const std::string& id, const std::string& password_hash) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE accounts SET password_hash = ?, updated_at = ? WHERE id = ?");
    bind_text(stmt.get(), 1, password_hash);
    sqlite3_bind_int64(stmt.get(), 2, now_seconds());
    bind_text(stmt.get(), 3, id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::vector<Account> IdentityStore::list_accounts(int limit, int offset) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT id, username, email, password_hash, display_name, avatar_url, is_admin, created_at, updated_at "
        "FROM accounts ORDER BY created_at DESC LIMIT ? OFFSET ?");
    sqlite3_bind_int(stmt.get(), 1, limit);
    sqlite3_bind_int(stmt.get(), 2, offset);

    std::vector<Account> accounts;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        Account a;
        a.id = col_text(stmt.get(), 0);
        a.username = col_text(stmt.get(), 1);
        a.email = col_text(stmt.get(), 2);
        a.password_hash = col_text(stmt.get(), 3);
        a.display_name = col_text(stmt.get(), 4);
        a.avatar_url = col_text(stmt.get(), 5);
        a.is_admin = sqlite3_column_int(stmt.get(), 6) != 0;
        a.created_at = sqlite3_column_int64(stmt.get(), 7);
        a.updated_at = sqlite3_column_int64(stmt.get(), 8);
        accounts.push_back(std::move(a));
    }
    return accounts;
}

bool IdentityStore::disable_account(const std::string& id) {
    std::lock_guard lock(mutex_);
    // Set password_hash to empty to disable login
    auto stmt = prepare(db_, "UPDATE accounts SET password_hash = '', updated_at = ? WHERE id = ?");
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    sqlite3_bind_int64(stmt.get(), 1, now);
    sqlite3_bind_text(stmt.get(), 2, id.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

// OAuth clients

bool IdentityStore::create_oauth_client(const OAuthClient& client) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO oauth_clients (client_id, client_secret, name, redirect_uris, created_at) "
        "VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, client.client_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, client.client_secret.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, client.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, client.redirect_uris.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 5, client.created_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<OAuthClient> IdentityStore::get_oauth_client(const std::string& client_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT client_id, client_secret, name, redirect_uris, created_at FROM oauth_clients WHERE client_id = ?");
    sqlite3_bind_text(stmt.get(), 1, client_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        OAuthClient c;
        c.client_id = col_text(stmt.get(), 0);
        c.client_secret = col_text(stmt.get(), 1);
        c.name = col_text(stmt.get(), 2);
        c.redirect_uris = col_text(stmt.get(), 3);
        c.created_at = sqlite3_column_int64(stmt.get(), 4);
        return c;
    }
    return std::nullopt;
}

std::vector<OAuthClient> IdentityStore::list_oauth_clients() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT client_id, client_secret, name, redirect_uris, created_at FROM oauth_clients ORDER BY created_at DESC");
    std::vector<OAuthClient> clients;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        OAuthClient c;
        c.client_id = col_text(stmt.get(), 0);
        c.client_secret = col_text(stmt.get(), 1);
        c.name = col_text(stmt.get(), 2);
        c.redirect_uris = col_text(stmt.get(), 3);
        c.created_at = sqlite3_column_int64(stmt.get(), 4);
        clients.push_back(std::move(c));
    }
    return clients;
}

bool IdentityStore::update_oauth_client_redirect_uris(const std::string& client_id,
                                                      const std::string& redirect_uris_json) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE oauth_clients SET redirect_uris = ? WHERE client_id = ?");
    bind_text(stmt.get(), 1, redirect_uris_json);
    bind_text(stmt.get(), 2, client_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

// Auth codes

bool IdentityStore::store_auth_code(const AuthCode& code) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO auth_codes (code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, code.code.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, code.client_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, code.account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, code.redirect_uri.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, code.scope.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, code.code_challenge.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 7, code.expires_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<AuthCode> IdentityStore::get_auth_code(const std::string& code) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at "
        "FROM auth_codes WHERE code = ?");
    sqlite3_bind_text(stmt.get(), 1, code.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        AuthCode ac;
        ac.code = col_text(stmt.get(), 0);
        ac.client_id = col_text(stmt.get(), 1);
        ac.account_id = col_text(stmt.get(), 2);
        ac.redirect_uri = col_text(stmt.get(), 3);
        ac.scope = col_text(stmt.get(), 4);
        ac.code_challenge = col_text(stmt.get(), 5);
        ac.expires_at = sqlite3_column_int64(stmt.get(), 6);
        return ac;
    }
    return std::nullopt;
}

void IdentityStore::delete_auth_code(const std::string& code) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM auth_codes WHERE code = ?");
    sqlite3_bind_text(stmt.get(), 1, code.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::optional<AuthCode> IdentityStore::consume_auth_code(const std::string& code) {
    std::lock_guard lock(mutex_);
    Transaction txn(db_);

    std::optional<AuthCode> result;
    {
        auto stmt = prepare(db_,
            "SELECT code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at "
            "FROM auth_codes WHERE code = ?");
        bind_text(stmt.get(), 1, code);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            AuthCode ac;
            ac.code = col_text(stmt.get(), 0);
            ac.client_id = col_text(stmt.get(), 1);
            ac.account_id = col_text(stmt.get(), 2);
            ac.redirect_uri = col_text(stmt.get(), 3);
            ac.scope = col_text(stmt.get(), 4);
            ac.code_challenge = col_text(stmt.get(), 5);
            ac.expires_at = sqlite3_column_int64(stmt.get(), 6);
            result = std::move(ac);
        }
    }

    if (result) {
        auto del = prepare(db_, "DELETE FROM auth_codes WHERE code = ?");
        bind_text(del.get(), 1, code);
        sqlite3_step(del.get());
        // If the DELETE affected no rows another transaction already consumed
        // the code; treat it as invalid rather than issuing a second token set.
        if (sqlite3_changes(db_) == 0) {
            result.reset();
        }
    }

    txn.commit();
    return result;
}

void IdentityStore::delete_expired_auth_codes() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM auth_codes WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    sqlite3_step(stmt.get());
}

// Refresh tokens

bool IdentityStore::store_refresh_token(const RefreshToken& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO refresh_tokens (token, client_id, account_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, token.token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, token.client_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, token.account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, token.scope.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 5, token.expires_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<RefreshToken> IdentityStore::get_refresh_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT token, client_id, account_id, scope, expires_at FROM refresh_tokens WHERE token = ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RefreshToken rt;
        rt.token = col_text(stmt.get(), 0);
        rt.client_id = col_text(stmt.get(), 1);
        rt.account_id = col_text(stmt.get(), 2);
        rt.scope = col_text(stmt.get(), 3);
        rt.expires_at = sqlite3_column_int64(stmt.get(), 4);
        return rt;
    }
    return std::nullopt;
}

void IdentityStore::delete_refresh_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM refresh_tokens WHERE token = ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void IdentityStore::delete_expired_refresh_tokens() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM refresh_tokens WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    sqlite3_step(stmt.get());
}

// Sessions

bool IdentityStore::create_session(const Session& session) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO sessions (session_id, account_id, created_at, expires_at, token_type, scope, client_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)");
    bind_text(stmt.get(), 1, session.session_id);
    bind_text(stmt.get(), 2, session.account_id);
    sqlite3_bind_int64(stmt.get(), 3, session.created_at);
    sqlite3_bind_int64(stmt.get(), 4, session.expires_at);
    bind_text(stmt.get(), 5, session.token_type);
    bind_text(stmt.get(), 6, session.scope);
    bind_text(stmt.get(), 7, session.client_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

namespace {

std::optional<Session> read_session_row(sqlite3_stmt* stmt) {
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    Session s;
    s.session_id = col_text(stmt, 0);
    s.account_id = col_text(stmt, 1);
    s.created_at = sqlite3_column_int64(stmt, 2);
    s.expires_at = sqlite3_column_int64(stmt, 3);
    s.token_type = col_text(stmt, 4);
    s.scope = col_text(stmt, 5);
    s.client_id = col_text(stmt, 6);
    return s;
}

constexpr const char* kSessionColumns =
    "SELECT session_id, account_id, created_at, expires_at, token_type, scope, client_id FROM sessions ";

} // namespace

std::optional<Session> IdentityStore::get_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) + "WHERE session_id = ?");
    bind_text(stmt.get(), 1, session_id);
    return read_session_row(stmt.get());
}

std::optional<Session> IdentityStore::get_browser_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) + "WHERE session_id = ? AND token_type = ?");
    bind_text(stmt.get(), 1, session_id);
    bind_text(stmt.get(), 2, token_type::kBrowserSession);
    return read_session_row(stmt.get());
}

std::optional<Session> IdentityStore::get_oidc_access_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) + "WHERE session_id = ? AND token_type = ?");
    bind_text(stmt.get(), 1, token);
    bind_text(stmt.get(), 2, token_type::kOidcAccess);
    return read_session_row(stmt.get());
}

void IdentityStore::delete_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE session_id = ?");
    sqlite3_bind_text(stmt.get(), 1, session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void IdentityStore::delete_expired_sessions() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    sqlite3_step(stmt.get());
}

std::vector<Session> IdentityStore::list_sessions_for_account(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) +
        "WHERE account_id = ? AND token_type = ? ORDER BY created_at DESC");
    bind_text(stmt.get(), 1, account_id);
    bind_text(stmt.get(), 2, token_type::kBrowserSession);

    std::vector<Session> sessions;
    while (auto s = read_session_row(stmt.get())) {
        sessions.push_back(std::move(*s));
    }
    return sessions;
}

// TOTP

void IdentityStore::set_totp_secret(const std::string& account_id, const std::string& secret,
                                    const std::vector<std::string>& backup_codes) {
    // Hash outside the lock — PBKDF2 over eight codes is not something to hold
    // the store mutex for.
    nlohmann::json hashed = nlohmann::json::array();
    for (const auto& code : backup_codes) {
        hashed.push_back(hash_password(code, kBackupCodeIterations));
    }
    auto hashed_json = hashed.dump();

    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR REPLACE INTO user_totp (account_id, secret, enabled, backup_codes) VALUES (?, ?, 0, ?)");
    bind_text(stmt.get(), 1, account_id);
    bind_text(stmt.get(), 2, secret);
    bind_text(stmt.get(), 3, hashed_json);
    sqlite3_step(stmt.get());
}

std::optional<TotpInfo> IdentityStore::get_totp(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT secret, enabled, backup_codes FROM user_totp WHERE account_id = ?");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        TotpInfo info;
        info.secret = col_text(stmt.get(), 0);
        info.enabled = sqlite3_column_int(stmt.get(), 1) != 0;
        info.backup_codes_json = col_text(stmt.get(), 2);
        return info;
    }
    return std::nullopt;
}

void IdentityStore::enable_totp(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE user_totp SET enabled = 1 WHERE account_id = ?");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void IdentityStore::disable_totp(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM user_totp WHERE account_id = ?");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

bool IdentityStore::consume_backup_code(const std::string& account_id, const std::string& code) {
    if (code.empty()) return false;

    std::lock_guard lock(mutex_);
    Transaction txn(db_);

    std::string codes_str;
    {
        auto stmt = prepare(db_, "SELECT backup_codes FROM user_totp WHERE account_id = ?");
        bind_text(stmt.get(), 1, account_id);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
            return false;
        }
        codes_str = col_text(stmt.get(), 0);
    }

    auto codes = nlohmann::json::parse(codes_str, nullptr, false);
    if (codes.is_discarded() || !codes.is_array()) {
        return false;
    }

    // Compare against every entry without breaking early, so a wrong code
    // always costs the same work regardless of position.
    size_t match_index = codes.size();
    for (size_t i = 0; i < codes.size(); ++i) {
        if (!codes[i].is_string()) continue;
        auto stored = codes[i].get<std::string>();
        bool ok = stored.rfind("$pbkdf2", 0) == 0
                      ? verify_password(code, stored)
                      // Legacy plaintext entry (pre-migration write from an
                      // older build); still accepted so nobody is locked out.
                      : constant_time_equals(stored, code);
        if (ok && match_index == codes.size()) {
            match_index = i;
        }
    }

    if (match_index == codes.size()) {
        return false;
    }

    codes.erase(codes.begin() + static_cast<long>(match_index));
    auto updated = codes.dump();

    auto update_stmt = prepare(db_, "UPDATE user_totp SET backup_codes = ? WHERE account_id = ?");
    bind_text(update_stmt.get(), 1, updated);
    bind_text(update_stmt.get(), 2, account_id);
    if (sqlite3_step(update_stmt.get()) != SQLITE_DONE || sqlite3_changes(db_) == 0) {
        return false; // roll back rather than accept a code we failed to burn
    }

    txn.commit();
    return true;
}

// Login tokens

void IdentityStore::create_login_token(const std::string& token, const std::string& account_id, int64_t expires_at) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO login_tokens (token, account_id, expires_at) VALUES (?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, expires_at);
    sqlite3_step(stmt.get());
}

std::optional<std::string> IdentityStore::validate_login_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto stmt = prepare(db_,
        "SELECT account_id FROM login_tokens WHERE token = ? AND expires_at > ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, now);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return col_text(stmt.get(), 0);
    }
    return std::nullopt;
}

void IdentityStore::delete_login_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM login_tokens WHERE token = ?");
    sqlite3_bind_text(stmt.get(), 1, token.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

bool IdentityStore::record_login_token_failure(const std::string& token, int max_attempts) {
    std::lock_guard lock(mutex_);
    Transaction txn(db_);

    int attempts = 0;
    {
        auto stmt = prepare(db_, "SELECT attempts FROM login_tokens WHERE token = ?");
        bind_text(stmt.get(), 1, token);
        if (sqlite3_step(stmt.get()) != SQLITE_ROW) {
            txn.commit();
            return true; // already gone
        }
        attempts = sqlite3_column_int(stmt.get(), 0);
    }

    attempts += 1;
    bool destroy = attempts >= max_attempts;

    if (destroy) {
        // Burn the token: a wrong second factor must not leave a credential
        // that can be retried for the remainder of its five minute lifetime.
        auto del = prepare(db_, "DELETE FROM login_tokens WHERE token = ?");
        bind_text(del.get(), 1, token);
        sqlite3_step(del.get());
    } else {
        auto upd = prepare(db_, "UPDATE login_tokens SET attempts = ? WHERE token = ?");
        sqlite3_bind_int(upd.get(), 1, attempts);
        bind_text(upd.get(), 2, token);
        sqlite3_step(upd.get());
    }

    txn.commit();
    return destroy;
}

void IdentityStore::delete_expired_login_tokens() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM login_tokens WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    sqlite3_step(stmt.get());
}

// Consent requests

bool IdentityStore::store_consent_request(const ConsentRequest& request) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO consent_requests "
        "(token, session_id, account_id, client_id, redirect_uri, scope, state, code_challenge, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    bind_text(stmt.get(), 1, request.token);
    bind_text(stmt.get(), 2, request.session_id);
    bind_text(stmt.get(), 3, request.account_id);
    bind_text(stmt.get(), 4, request.client_id);
    bind_text(stmt.get(), 5, request.redirect_uri);
    bind_text(stmt.get(), 6, request.scope);
    bind_text(stmt.get(), 7, request.state);
    bind_text(stmt.get(), 8, request.code_challenge);
    sqlite3_bind_int64(stmt.get(), 9, request.expires_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<ConsentRequest> IdentityStore::consume_consent_request(const std::string& token,
                                                                     const std::string& session_id) {
    if (token.empty() || session_id.empty()) return std::nullopt;

    std::lock_guard lock(mutex_);
    Transaction txn(db_);

    std::optional<ConsentRequest> result;
    {
        // Matching the session in SQL means a decision posted from any other
        // session simply finds nothing, and deletes nothing.
        auto stmt = prepare(db_,
            "SELECT token, session_id, account_id, client_id, redirect_uri, scope, state, code_challenge, expires_at "
            "FROM consent_requests WHERE token = ? AND session_id = ?");
        bind_text(stmt.get(), 1, token);
        bind_text(stmt.get(), 2, session_id);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
            ConsentRequest r;
            r.token = col_text(stmt.get(), 0);
            r.session_id = col_text(stmt.get(), 1);
            r.account_id = col_text(stmt.get(), 2);
            r.client_id = col_text(stmt.get(), 3);
            r.redirect_uri = col_text(stmt.get(), 4);
            r.scope = col_text(stmt.get(), 5);
            r.state = col_text(stmt.get(), 6);
            r.code_challenge = col_text(stmt.get(), 7);
            r.expires_at = sqlite3_column_int64(stmt.get(), 8);
            result = std::move(r);
        }
    }

    if (result) {
        auto del = prepare(db_, "DELETE FROM consent_requests WHERE token = ? AND session_id = ?");
        bind_text(del.get(), 1, token);
        bind_text(del.get(), 2, session_id);
        sqlite3_step(del.get());
        // Lost the race with a concurrent decision — do not issue a second code.
        if (sqlite3_changes(db_) == 0) result.reset();
    }

    txn.commit();
    return result;
}

void IdentityStore::delete_expired_consent_requests() {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM consent_requests WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    sqlite3_step(stmt.get());
}

void IdentityStore::sweep_expired() {
    delete_expired_sessions();
    delete_expired_auth_codes();
    delete_expired_login_tokens();
    delete_expired_consent_requests();
    delete_expired_refresh_tokens();
}

// Server memberships

void IdentityStore::add_server_membership(const std::string& account_id,
                                           const std::string& server_url,
                                           const std::string& server_name) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR REPLACE INTO server_memberships (account_id, server_url, server_name, joined_at) "
        "VALUES (?, ?, ?, strftime('%s','now'))");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, server_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, server_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void IdentityStore::remove_server_membership(const std::string& account_id,
                                              const std::string& server_url) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "DELETE FROM server_memberships WHERE account_id = ? AND server_url = ?");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, server_url.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

std::vector<IdentityStore::ServerMembership>
IdentityStore::list_server_memberships(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT id, server_url, server_name, joined_at "
        "FROM server_memberships WHERE account_id = ? ORDER BY joined_at ASC");
    sqlite3_bind_text(stmt.get(), 1, account_id.c_str(), -1, SQLITE_TRANSIENT);
    std::vector<ServerMembership> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        ServerMembership m;
        m.id = std::to_string(sqlite3_column_int64(stmt.get(), 0));
        m.server_url = col_text(stmt.get(), 1);
        m.server_name = col_text(stmt.get(), 2);
        m.joined_at = sqlite3_column_int64(stmt.get(), 3);
        out.push_back(std::move(m));
    }
    return out;
}

} // namespace bsfchat::id
