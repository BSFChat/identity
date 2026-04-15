#include "store/IdentityStore.h"
#include "core/Logger.h"

#include <stdexcept>

namespace bsfchat::id {

namespace {

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

    exec("CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username)");
    exec("CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id)");
    exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_account ON refresh_tokens(account_id)");
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

// Sessions

bool IdentityStore::create_session(const Session& session) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT INTO sessions (session_id, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, session.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, session.account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, session.created_at);
    sqlite3_bind_int64(stmt.get(), 4, session.expires_at);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<Session> IdentityStore::get_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT session_id, account_id, created_at, expires_at FROM sessions WHERE session_id = ?");
    sqlite3_bind_text(stmt.get(), 1, session_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        Session s;
        s.session_id = col_text(stmt.get(), 0);
        s.account_id = col_text(stmt.get(), 1);
        s.created_at = sqlite3_column_int64(stmt.get(), 2);
        s.expires_at = sqlite3_column_int64(stmt.get(), 3);
        return s;
    }
    return std::nullopt;
}

void IdentityStore::delete_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE session_id = ?");
    sqlite3_bind_text(stmt.get(), 1, session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt.get());
}

void IdentityStore::delete_expired_sessions() {
    std::lock_guard lock(mutex_);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE expires_at < ?");
    sqlite3_bind_int64(stmt.get(), 1, now);
    sqlite3_step(stmt.get());
}

} // namespace bsfchat::id
