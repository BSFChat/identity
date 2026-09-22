#include "store/IdentityStore.h"
#include "core/Logger.h"
#include "core/WebUtil.h"
#include "core/Username.h"
#include "crypto/PasswordHash.h"
#include "crypto/Secrets.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace bsfchat::id {

namespace {

// Bump when a new migration step is appended to migrate_locked().
constexpr int kSchemaVersion = 3;

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
            expires_at INTEGER NOT NULL,
            resource TEXT NOT NULL DEFAULT '',
            nonce TEXT NOT NULL DEFAULT ''
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
            expires_at     INTEGER NOT NULL,
            resource       TEXT NOT NULL DEFAULT '',
            nonce          TEXT NOT NULL DEFAULT ''
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
    if (version < 1) {
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

        exec("PRAGMA user_version = 1");
        log->info("Identity database schema migrated to version 1");
    }

    // --- v2: bind a grant to the chat server it is for, and carry a nonce ---
    //
    // Identity audit 2026-09, finding C1: every id_token was audienced to the
    // desktop client_id, so one token signed its holder in at EVERY chat
    // server. The authorization request now names the server (RFC 8707
    // `resource`) and the id_token is audienced to it; both rows that carry
    // a grant from /authorize to /token have to carry that, and the nonce.
    // Both tables hold rows that live five minutes, so nothing is backfilled:
    // a pending grant from before the upgrade simply has no resource, and
    // gets the legacy audience that upgraded chat servers refuse.
    //
    // The column checks run whatever user_version says (they are cheap and
    // guarded): before the two audit branches were integrated,
    // fix/security-audit-2026-09 ALSO called its migration "v2", so a
    // development database that ran that branch says user_version = 2 but
    // has no resource/nonce columns. Keying this step on the version alone
    // would skip it there and every /authorize would then fail in prepare().
    {
        for (const char* table : {"auth_codes", "consent_requests"}) {
            if (!has_column_locked(table, "resource")) {
                exec(std::string("ALTER TABLE ") + table +
                     " ADD COLUMN resource TEXT NOT NULL DEFAULT ''");
            }
            if (!has_column_locked(table, "nonce")) {
                exec(std::string("ALTER TABLE ") + table +
                     " ADD COLUMN nonce TEXT NOT NULL DEFAULT ''");
            }
        }
        if (version < 2) {
            exec("PRAGMA user_version = 2");
            log->info("Identity database schema migrated to version 2");
        }
    }

    // --- v3: security audit 2026-09 ------------------------------------------
    // Disabled accounts (H1), username skeletons (H3), TOTP replay (M2),
    // refresh-token families with an absolute lifetime (H4/L4), and no bearer
    // credential or client secret stored in the clear (L5).
    //
    // Written as "v2" on fix/security-audit-2026-09 and renumbered to v3 when
    // it was integrated after the audience-binding v2 above (C1); the two
    // touch different columns. C1's resource/nonce columns on auth_codes and
    // consent_requests are not secrets (a public server URL and a nonce that
    // is echoed into the id_token), and the consent_requests rehash below
    // rewrites session_id only, by value, so it leaves them intact.
    //
    // One transaction, so a failure part-way leaves the database at v2 rather
    // than half-hashed. Every step is additive; no row is dropped. Existing
    // sessions and refresh tokens keep working, because lookups hash the
    // presented value and the rows are hashed here to match.
    if (version < 3) {
        Transaction txn(db_);

        // Hashing is not idempotent, so it is tied to a column this same step
        // creates rather than to user_version alone: a database whose
        // user_version was lost must not have its tokens hashed twice (which
        // would sign everybody out). Still the right marker at v3: nothing
        // in v1 or v2 creates refresh_tokens.family_id, and a database that
        // ran the pre-integration "v2" of this step (user_version 2, family_id
        // present) re-enters here and correctly skips the hashing.
        const bool hash_credentials = !has_column_locked("refresh_tokens", "family_id");

        if (!has_column_locked("accounts", "disabled_at")) {
            exec("ALTER TABLE accounts ADD COLUMN disabled_at INTEGER NOT NULL DEFAULT 0");
        }
        if (!has_column_locked("accounts", "username_skeleton")) {
            exec("ALTER TABLE accounts ADD COLUMN username_skeleton TEXT NOT NULL DEFAULT ''");
        }
        {
            std::vector<std::pair<std::string, std::string>> rows;
            auto stmt = prepare(db_, "SELECT id, username FROM accounts WHERE username_skeleton = ''");
            while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                rows.emplace_back(col_text(stmt.get(), 0), username_skeleton(col_text(stmt.get(), 1)));
            }
            auto upd = prepare(db_, "UPDATE accounts SET username_skeleton = ? WHERE id = ?");
            for (const auto& [id, skeleton] : rows) {
                sqlite3_reset(upd.get());
                bind_text(upd.get(), 1, skeleton);
                bind_text(upd.get(), 2, id);
                sqlite3_step(upd.get());
            }
        }
        exec("CREATE INDEX IF NOT EXISTS idx_accounts_username_skeleton ON accounts(username_skeleton)");
        {
            // Pre-policy lookalikes are left alone (refusing an existing
            // user's login would be worse), but the operator should know.
            auto stmt = prepare(db_,
                "SELECT COUNT(*) FROM (SELECT username_skeleton FROM accounts "
                "GROUP BY username_skeleton HAVING COUNT(*) > 1)");
            if (sqlite3_step(stmt.get()) == SQLITE_ROW && sqlite3_column_int(stmt.get(), 0) > 0) {
                log->warn("Schema migration: {} group(s) of existing usernames are confusable with "
                          "each other; they keep working, new lookalikes are refused",
                          sqlite3_column_int(stmt.get(), 0));
            }
        }

        if (!has_column_locked("user_totp", "last_step")) {
            exec("ALTER TABLE user_totp ADD COLUMN last_step INTEGER NOT NULL DEFAULT 0");
        }

        if (!has_column_locked("refresh_tokens", "family_id")) {
            exec("ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''");
        }
        if (!has_column_locked("refresh_tokens", "family_expires_at")) {
            exec("ALTER TABLE refresh_tokens ADD COLUMN family_expires_at INTEGER NOT NULL DEFAULT 0");
        }
        if (!has_column_locked("refresh_tokens", "created_at")) {
            exec("ALTER TABLE refresh_tokens ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0");
        }
        if (!has_column_locked("refresh_tokens", "replaced_at")) {
            exec("ALTER TABLE refresh_tokens ADD COLUMN replaced_at INTEGER NOT NULL DEFAULT 0");
        }
        // Every pre-existing token is its own family. Its absolute expiry is
        // its current expiry plus 60 days: the 90-day default less the 30 it
        // was last issued with, so nobody is signed out by the upgrade and no
        // token in circulation lives past about 90 days from now.
        exec("UPDATE refresh_tokens SET family_id = lower(hex(randomblob(16))) WHERE family_id = ''");
        exec("UPDATE refresh_tokens SET family_expires_at = expires_at + 5184000 WHERE family_expires_at = 0");
        exec("UPDATE refresh_tokens SET created_at = expires_at - 2592000 WHERE created_at = 0");
        exec("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family_id)");

        if (hash_credentials) {
            const auto rehash = [&](const char* table, const char* column) {
                std::vector<std::string> values;
                {
                    auto stmt = prepare(db_, std::string("SELECT ") + column + " FROM " + table);
                    while (sqlite3_step(stmt.get()) == SQLITE_ROW) values.push_back(col_text(stmt.get(), 0));
                }
                auto upd = prepare(db_, std::string("UPDATE ") + table + " SET " + column +
                                            " = ? WHERE " + column + " = ?");
                for (const auto& v : values) {
                    sqlite3_reset(upd.get());
                    bind_text(upd.get(), 1, hash_token(v));
                    bind_text(upd.get(), 2, v);
                    sqlite3_step(upd.get());
                }
                log->info("Schema migration: hashed {} {}.{} value(s) at rest", values.size(), table, column);
            };
            rehash("sessions", "session_id");
            rehash("refresh_tokens", "token");
            rehash("consent_requests", "session_id");
        }

        // Client secrets carry their own prefix, so this is idempotent alone.
        {
            std::vector<std::pair<std::string, std::string>> rows;
            auto stmt = prepare(db_, "SELECT client_id, client_secret FROM oauth_clients");
            while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
                auto secret = col_text(stmt.get(), 1);
                if (secret.empty() || secret.rfind(kClientSecretHashPrefix, 0) == 0) continue;
                rows.emplace_back(col_text(stmt.get(), 0), hash_client_secret(secret));
            }
            auto upd = prepare(db_, "UPDATE oauth_clients SET client_secret = ? WHERE client_id = ?");
            for (const auto& [id, hashed] : rows) {
                sqlite3_reset(upd.get());
                bind_text(upd.get(), 1, hashed);
                bind_text(upd.get(), 2, id);
                sqlite3_step(upd.get());
            }
            if (!rows.empty()) log->info("Schema migration: hashed {} OAuth client secret(s)", rows.size());
        }

        exec("PRAGMA user_version = 3");
        txn.commit();
        log->info("Identity database schema migrated to version {}", kSchemaVersion);
    }
}

// Accounts

namespace {

constexpr const char* kAccountColumns =
    "SELECT id, username, email, password_hash, display_name, avatar_url, is_admin, created_at, "
    "updated_at, disabled_at FROM accounts ";

Account read_account_row(sqlite3_stmt* stmt) {
    Account a;
    a.id = col_text(stmt, 0);
    a.username = col_text(stmt, 1);
    a.email = col_text(stmt, 2);
    a.password_hash = col_text(stmt, 3);
    a.display_name = col_text(stmt, 4);
    a.avatar_url = col_text(stmt, 5);
    a.is_admin = sqlite3_column_int(stmt, 6) != 0;
    a.created_at = sqlite3_column_int64(stmt, 7);
    a.updated_at = sqlite3_column_int64(stmt, 8);
    a.disabled_at = sqlite3_column_int64(stmt, 9);
    return a;
}

// Appended to credential lookups so a disabled account's rows resolve to
// nothing even if something were to survive disable_account()'s purge.
std::string account_enabled(const char* table) {
    return std::string(" AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.id = ") + table +
           ".account_id AND a.disabled_at != 0)";
}

} // namespace

bool IdentityStore::create_account(const Account& account) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO accounts (id, username, email, password_hash, display_name, avatar_url, is_admin, "
        "created_at, updated_at, username_skeleton) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
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
    bind_text(stmt.get(), 10, username_skeleton(account.username));
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

std::optional<Account> IdentityStore::get_account_by_id(const std::string& id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kAccountColumns) + "WHERE id = ?");
    bind_text(stmt.get(), 1, id);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return read_account_row(stmt.get());
    return std::nullopt;
}

std::optional<Account> IdentityStore::get_account_by_username(const std::string& username) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kAccountColumns) + "WHERE username = ?");
    bind_text(stmt.get(), 1, username);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return read_account_row(stmt.get());
    return std::nullopt;
}

std::optional<std::string> IdentityStore::find_account_by_username_skeleton(const std::string& skeleton) {
    if (skeleton.empty()) return std::nullopt;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT id FROM accounts WHERE username_skeleton = ? LIMIT 1");
    bind_text(stmt.get(), 1, skeleton);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return col_text(stmt.get(), 0);
    return std::nullopt;
}

bool IdentityStore::email_in_use(const std::string& email, const std::string& except_account_id) {
    if (email.empty()) return false;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "SELECT 1 FROM accounts WHERE email = ? AND id != ?");
    bind_text(stmt.get(), 1, email);
    bind_text(stmt.get(), 2, except_account_id);
    return sqlite3_step(stmt.get()) == SQLITE_ROW;
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
    auto stmt = prepare(db_, std::string(kAccountColumns) + "ORDER BY created_at DESC LIMIT ? OFFSET ?");
    sqlite3_bind_int(stmt.get(), 1, limit);
    sqlite3_bind_int(stmt.get(), 2, offset);

    std::vector<Account> accounts;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        accounts.push_back(read_account_row(stmt.get()));
    }
    return accounts;
}

int IdentityStore::revoke_credentials_locked(const std::string& account_id, const std::string& keep_hash) {
    int ended = 0;
    const auto run = [&](const char* sql, bool with_keep) {
        auto stmt = prepare(db_, sql);
        bind_text(stmt.get(), 1, account_id);
        if (with_keep) bind_text(stmt.get(), 2, keep_hash);
        sqlite3_step(stmt.get());
        return sqlite3_changes(db_);
    };
    {
        // Counted before deleting: the user-facing number is browser sessions
        // and refresh-token families, not access tokens or rotated-out rows.
        auto stmt = prepare(db_,
            "SELECT (SELECT COUNT(*) FROM sessions WHERE account_id = ?1 AND token_type = ?2 "
            "AND session_id != ?3) + "
            "(SELECT COUNT(DISTINCT family_id) FROM refresh_tokens WHERE account_id = ?1 AND replaced_at = 0)");
        bind_text(stmt.get(), 1, account_id);
        bind_text(stmt.get(), 2, token_type::kBrowserSession);
        bind_text(stmt.get(), 3, keep_hash);
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) ended = sqlite3_column_int(stmt.get(), 0);
    }
    run("DELETE FROM sessions WHERE account_id = ? AND session_id != ?", true);
    run("DELETE FROM refresh_tokens WHERE account_id = ?", false);
    // A code issued before the change could otherwise still be redeemed for
    // a fresh refresh token afterwards.
    run("DELETE FROM auth_codes WHERE account_id = ?", false);
    run("DELETE FROM login_tokens WHERE account_id = ?", false);
    run("DELETE FROM consent_requests WHERE account_id = ? AND session_id != ?", true);
    return ended;
}

bool IdentityStore::disable_account(const std::string& id) {
    std::lock_guard lock(mutex_);
    Transaction txn(db_);
    // The password hash is kept so that re-enabling restores the account as
    // it was. Nothing authenticates a disabled account: login refuses it and
    // every credential lookup filters it out.
    auto stmt = prepare(db_,
        "UPDATE accounts SET disabled_at = CASE WHEN disabled_at = 0 THEN ?1 ELSE disabled_at END, "
        "updated_at = ?1 WHERE id = ?2");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    bind_text(stmt.get(), 2, id);
    if (sqlite3_step(stmt.get()) != SQLITE_DONE || sqlite3_changes(db_) == 0) return false;
    revoke_credentials_locked(id, "");
    txn.commit();
    return true;
}

bool IdentityStore::enable_account(const std::string& id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "UPDATE accounts SET disabled_at = 0, updated_at = ? WHERE id = ?");
    sqlite3_bind_int64(stmt.get(), 1, now_seconds());
    bind_text(stmt.get(), 2, id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

int IdentityStore::revoke_account_credentials(const std::string& account_id,
                                              const std::string& keep_session_id) {
    std::lock_guard lock(mutex_);
    Transaction txn(db_);
    // An empty keep value must not match anything; a hash never equals "".
    auto ended = revoke_credentials_locked(account_id,
                                           keep_session_id.empty() ? "" : hash_token(keep_session_id));
    txn.commit();
    return ended;
}

// OAuth clients

bool IdentityStore::create_oauth_client(const OAuthClient& client) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "INSERT OR IGNORE INTO oauth_clients (client_id, client_secret, name, redirect_uris, created_at) "
        "VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, client.client_id.c_str(), -1, SQLITE_TRANSIENT);
    // Only the digest is kept (security audit L5); the plaintext is shown to
    // the admin once, in the creation response, and never again.
    const bool already_hashed = client.client_secret.rfind(kClientSecretHashPrefix, 0) == 0;
    bind_text(stmt.get(), 2, client.client_secret.empty() || already_hashed
                                 ? client.client_secret
                                 : hash_client_secret(client.client_secret));
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
        "INSERT INTO auth_codes (code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at, "
        "resource, nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    sqlite3_bind_text(stmt.get(), 1, code.code.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, code.client_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, code.account_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 4, code.redirect_uri.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 5, code.scope.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 6, code.code_challenge.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 7, code.expires_at);
    bind_text(stmt.get(), 8, code.resource);
    bind_text(stmt.get(), 9, code.nonce);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<AuthCode> IdentityStore::get_auth_code(const std::string& code) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "SELECT code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at, "
        "resource, nonce FROM auth_codes WHERE code = ?");
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
        ac.resource = col_text(stmt.get(), 7);
        ac.nonce = col_text(stmt.get(), 8);
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
            "SELECT code, client_id, account_id, redirect_uri, scope, code_challenge, expires_at, "
            "resource, nonce FROM auth_codes WHERE code = ?");
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
        ac.resource = col_text(stmt.get(), 7);
        ac.nonce = col_text(stmt.get(), 8);
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

namespace {

constexpr const char* kRefreshColumns =
    "SELECT token, client_id, account_id, scope, expires_at, family_id, family_expires_at, "
    "created_at, replaced_at FROM refresh_tokens ";

RefreshToken read_refresh_row(sqlite3_stmt* stmt) {
    RefreshToken rt;
    rt.token = col_text(stmt, 0);
    rt.client_id = col_text(stmt, 1);
    rt.account_id = col_text(stmt, 2);
    rt.scope = col_text(stmt, 3);
    rt.expires_at = sqlite3_column_int64(stmt, 4);
    rt.family_id = col_text(stmt, 5);
    rt.family_expires_at = sqlite3_column_int64(stmt, 6);
    rt.created_at = sqlite3_column_int64(stmt, 7);
    rt.replaced_at = sqlite3_column_int64(stmt, 8);
    return rt;
}

bool insert_refresh_row(sqlite3* db, const RefreshToken& token) {
    auto stmt = prepare(db,
        "INSERT INTO refresh_tokens (token, client_id, account_id, scope, expires_at, family_id, "
        "family_expires_at, created_at, replaced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)");
    bind_text(stmt.get(), 1, hash_token(token.token));
    bind_text(stmt.get(), 2, token.client_id);
    bind_text(stmt.get(), 3, token.account_id);
    bind_text(stmt.get(), 4, token.scope);
    sqlite3_bind_int64(stmt.get(), 5, token.expires_at);
    // A caller that predates families still gets one: its own.
    bind_text(stmt.get(), 6, token.family_id.empty() ? hash_token(token.token).substr(0, 32)
                                                      : token.family_id);
    sqlite3_bind_int64(stmt.get(), 7, token.family_expires_at ? token.family_expires_at : token.expires_at);
    sqlite3_bind_int64(stmt.get(), 8, token.created_at ? token.created_at : now_seconds());
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

} // namespace

bool IdentityStore::store_refresh_token(const RefreshToken& token) {
    std::lock_guard lock(mutex_);
    return insert_refresh_row(db_, token);
}

std::optional<RefreshToken> IdentityStore::get_refresh_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kRefreshColumns) + "WHERE token = ?" +
                                 account_enabled("refresh_tokens"));
    bind_text(stmt.get(), 1, hash_token(token));
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) return read_refresh_row(stmt.get());
    return std::nullopt;
}

void IdentityStore::delete_refresh_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM refresh_tokens WHERE token = ?");
    bind_text(stmt.get(), 1, hash_token(token));
    sqlite3_step(stmt.get());
}

RotateResult IdentityStore::rotate_refresh_token(const std::string& old_token,
                                                 const RefreshToken& replacement) {
    std::lock_guard lock(mutex_);
    Transaction txn(db_);

    std::optional<RefreshToken> current;
    {
        auto stmt = prepare(db_, std::string(kRefreshColumns) + "WHERE token = ?" +
                                     account_enabled("refresh_tokens"));
        bind_text(stmt.get(), 1, hash_token(old_token));
        if (sqlite3_step(stmt.get()) == SQLITE_ROW) current = read_refresh_row(stmt.get());
    }
    if (!current) return RotateResult::Invalid;

    if (current->replaced_at != 0) {
        // A retired token came back. Either the client is replaying (it lost
        // the response and retried — its family is dead to it anyway, since it
        // never received the successor) or somebody else holds a copy. Kill
        // the family so the copy stops working too (OAuth 2.0 Security BCP,
        // refresh token rotation).
        auto del = prepare(db_, "DELETE FROM refresh_tokens WHERE family_id = ?");
        bind_text(del.get(), 1, current->family_id);
        sqlite3_step(del.get());
        txn.commit();
        return RotateResult::Reused;
    }

    const auto now = now_seconds();
    if (current->expires_at < now || current->family_expires_at < now) {
        auto del = prepare(db_, "DELETE FROM refresh_tokens WHERE family_id = ?");
        bind_text(del.get(), 1, current->family_id);
        sqlite3_step(del.get());
        txn.commit();
        return RotateResult::Invalid;
    }

    {
        auto upd = prepare(db_, "UPDATE refresh_tokens SET replaced_at = ? WHERE token = ? AND replaced_at = 0");
        sqlite3_bind_int64(upd.get(), 1, now);
        bind_text(upd.get(), 2, current->token); // already the stored hash
        if (sqlite3_step(upd.get()) != SQLITE_DONE || sqlite3_changes(db_) == 0) {
            return RotateResult::Invalid;
        }
    }

    // The successor inherits the family and its absolute expiry whatever the
    // caller filled in: rotation must not be able to extend a grant.
    RefreshToken next = replacement;
    next.family_id = current->family_id;
    next.family_expires_at = current->family_expires_at;
    next.created_at = current->created_at;
    next.account_id = current->account_id;
    next.client_id = current->client_id;
    next.scope = current->scope;
    if (next.expires_at > next.family_expires_at) next.expires_at = next.family_expires_at;
    if (!insert_refresh_row(db_, next)) return RotateResult::Invalid;

    txn.commit();
    return RotateResult::Rotated;
}

void IdentityStore::revoke_refresh_token_family(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_,
        "DELETE FROM refresh_tokens WHERE family_id = "
        "(SELECT family_id FROM refresh_tokens WHERE token = ?)");
    bind_text(stmt.get(), 1, hash_token(token));
    sqlite3_step(stmt.get());
}

std::vector<RefreshToken> IdentityStore::list_refresh_tokens_for_account(const std::string& account_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kRefreshColumns) +
        "WHERE account_id = ? AND replaced_at = 0 AND expires_at >= ? ORDER BY created_at DESC");
    bind_text(stmt.get(), 1, account_id);
    sqlite3_bind_int64(stmt.get(), 2, now_seconds());
    std::vector<RefreshToken> out;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) out.push_back(read_refresh_row(stmt.get()));
    return out;
}

bool IdentityStore::delete_refresh_family(const std::string& account_id, const std::string& family_id) {
    if (family_id.empty()) return false;
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM refresh_tokens WHERE account_id = ? AND family_id = ?");
    bind_text(stmt.get(), 1, account_id);
    bind_text(stmt.get(), 2, family_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
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
    bind_text(stmt.get(), 1, hash_token(session.session_id));
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
    bind_text(stmt.get(), 1, hash_token(session_id));
    return read_session_row(stmt.get());
}

std::optional<Session> IdentityStore::get_browser_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) + "WHERE session_id = ? AND token_type = ?" +
                                 account_enabled("sessions"));
    bind_text(stmt.get(), 1, hash_token(session_id));
    bind_text(stmt.get(), 2, token_type::kBrowserSession);
    return read_session_row(stmt.get());
}

std::optional<Session> IdentityStore::get_oidc_access_token(const std::string& token) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, std::string(kSessionColumns) + "WHERE session_id = ? AND token_type = ?" +
                                 account_enabled("sessions"));
    bind_text(stmt.get(), 1, hash_token(token));
    bind_text(stmt.get(), 2, token_type::kOidcAccess);
    return read_session_row(stmt.get());
}

void IdentityStore::delete_session(const std::string& session_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE session_id = ?");
    bind_text(stmt.get(), 1, hash_token(session_id));
    sqlite3_step(stmt.get());
}

bool IdentityStore::delete_stored_session(const std::string& account_id, const std::string& stored_id) {
    std::lock_guard lock(mutex_);
    auto stmt = prepare(db_, "DELETE FROM sessions WHERE account_id = ? AND session_id = ?");
    bind_text(stmt.get(), 1, account_id);
    bind_text(stmt.get(), 2, stored_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
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

bool IdentityStore::accept_totp_step(const std::string& account_id, uint64_t step) {
    std::lock_guard lock(mutex_);
    // Compare-and-set in one statement, so two logins racing with the same
    // code cannot both see the old value.
    auto stmt = prepare(db_, "UPDATE user_totp SET last_step = ?1 WHERE account_id = ?2 AND last_step < ?1");
    sqlite3_bind_int64(stmt.get(), 1, static_cast<int64_t>(step));
    bind_text(stmt.get(), 2, account_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
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
        "(token, session_id, account_id, client_id, redirect_uri, scope, state, code_challenge, expires_at, "
        "resource, nonce) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    bind_text(stmt.get(), 1, request.token);
    // The browser session this prompt is bound to, hashed like the sessions
    // table itself: the raw value would be a live session id at rest.
    bind_text(stmt.get(), 2, hash_token(request.session_id));
    bind_text(stmt.get(), 3, request.account_id);
    bind_text(stmt.get(), 4, request.client_id);
    bind_text(stmt.get(), 5, request.redirect_uri);
    bind_text(stmt.get(), 6, request.scope);
    bind_text(stmt.get(), 7, request.state);
    bind_text(stmt.get(), 8, request.code_challenge);
    sqlite3_bind_int64(stmt.get(), 9, request.expires_at);
    bind_text(stmt.get(), 10, request.resource);
    bind_text(stmt.get(), 11, request.nonce);
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
            "SELECT token, session_id, account_id, client_id, redirect_uri, scope, state, code_challenge, expires_at, "
            "resource, nonce FROM consent_requests WHERE token = ? AND session_id = ?");
        bind_text(stmt.get(), 1, token);
        bind_text(stmt.get(), 2, hash_token(session_id));
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
            r.resource = col_text(stmt.get(), 9);
            r.nonce = col_text(stmt.get(), 10);
            result = std::move(r);
        }
    }

    if (result) {
        auto del = prepare(db_, "DELETE FROM consent_requests WHERE token = ? AND session_id = ?");
        bind_text(del.get(), 1, token);
        bind_text(del.get(), 2, hash_token(session_id));
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
