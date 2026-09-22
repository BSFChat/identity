#include "api/AccountHandler.h"
#include "crypto/PasswordHash.h"
#include "crypto/Secrets.h"
#include "crypto/Totp.h"
#include "core/Logger.h"
#include "core/Username.h"
#include "core/WebUtil.h"

#include <bsfchat/Identifiers.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace bsfchat::id {

namespace {

using json = nlohmann::json;

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string generate_uuid() {
    unsigned char bytes[16];
    secure_random_bytes(bytes, sizeof(bytes));
    // Set version 4 and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) ss << '-';
    }
    return ss.str();
}

std::string generate_session_id() {
    return secure_random_hex(32);
}

constexpr int kSessionLifetimeSeconds = 86400 * 7;
constexpr size_t kMaxPasswordLength = 1024;

void json_error(httplib::Response& res, int status, const std::string& error) {
    res.status = status;
    res.set_content(json{{"error", error}}.dump(), "application/json");
}

// Reads the `session` cookie with a real cookie parser. The previous
// `cookie.find("session=")` substring search also matched "mysession=".
std::string extract_session_id(const httplib::Request& req) {
    if (!req.has_header("Cookie")) return "";
    auto value = get_cookie(req.get_header_value("Cookie"), "session");
    return value.value_or("");
}

// Bearer token presented on the request, if any.
std::string extract_bearer_token(const httplib::Request& req) {
    if (!req.has_header("Authorization")) return "";
    auto auth = req.get_header_value("Authorization");
    if (!auth.starts_with("Bearer ")) return "";
    return auth.substr(7);
}

// Scope an OIDC access token must carry to reach the server-membership API.
//
// Ideally this would be a dedicated `bsfchat:servers` scope, but the shipped
// desktop client requests exactly "openid profile" and relies on the resulting
// access token for /api/servers, so requiring a new scope would break it.
// `openid` is therefore the bar here — and only here. Account management,
// session control, 2FA and admin remain browser-session only.
constexpr const char* kServersScope = "openid";

// ...and the only OAuth client whose access token may reach it (identity
// audit 2026-09, M5). The scope bar above is one every relying party clears,
// so any registered client — a bot dashboard, a third-party web app — could
// rewrite the list of servers the desktop app auto-connects to and signs in
// to. That list is the desktop app's own state; nobody else has a reason to
// write it. Seeded in IdentityServer.cpp. A browser session (the portal's
// own profile page) is unaffected.
constexpr const char* kServerListClientId = "bsfchat-desktop";

bool may_use_server_list(const AuthContext& ctx) {
    return ctx.authenticated() &&
           (ctx.is_browser_session() || ctx.client_id == kServerListClientId);
}

// Bounds on a server-membership row. The desktop client walks this list on
// login and connects to each entry, so a hostile value here is a hostile
// value in somebody's client, and the token that can write it only has to
// carry the "openid" scope that every relying party asks for.
constexpr size_t kMaxServerUrlLength = 512;
constexpr size_t kMaxServerNameLength = 128;
constexpr size_t kMaxServerMemberships = 100;

// Characters a homeserver or avatar URL never needs, and which are exactly the
// ones that break out of an HTML attribute or a JS string: security audit M1
// stored `https://x.example/');alert(document.domain);//` and the portal ran
// it. The page no longer builds handlers from strings, but data that reaches
// three different renderers (the portal, the desktop client, chat servers
// via the id_token's `picture`) should be inert on its own.
bool has_markup_characters(const std::string& s) {
    return s.find_first_of("'\"<>`\\(){}|^ ") != std::string::npos;
}

// The list used to take any string at all: `file:///etc/passwd`,
// `javascript:…`, or `https://real.example@evil.example/` (userinfo
// smuggling, which parse_uri rejects outright). There is no reason for a
// homeserver URL to be anything but absolute http(s) with a host.
bool server_url_acceptable(const std::string& url, std::string& why) {
    if (url.empty() || url.size() > kMaxServerUrlLength) {
        why = "server_url must be 1-512 characters";
        return false;
    }
    if (std::any_of(url.begin(), url.end(),
                    [](unsigned char c) { return c < 0x21 || c == 0x7f; }) ||
        has_markup_characters(url)) {
        why = "server_url contains invalid characters";
        return false;
    }
    const auto uri = parse_uri(url);
    if (!uri.valid || uri.host.empty()) {
        why = "server_url must be an absolute URL with a host";
        return false;
    }
    if (uri.scheme != "http" && uri.scheme != "https") {
        why = "server_url must use http or https";
        return false;
    }
    if (uri.has_fragment) {
        why = "server_url must not have a fragment";
        return false;
    }
    return true;
}

std::string generate_hex_token(int bytes) {
    return secure_random_hex(static_cast<size_t>(bytes));
}

// Reads a string member, treating absence or any other JSON type as empty.
// body.value("k", "") throws json::type_error for {"k": 1}, which httplib
// turns into a 500 rather than the 400 a malformed request deserves.
std::string string_field(const json& body, const char* key) {
    auto it = body.find(key);
    if (it == body.end() || !it->is_string()) return "";
    return it->get<std::string>();
}

// Parses a JSON object body; writes a 400 and returns nullopt otherwise.
std::optional<json> parse_object(const httplib::Request& req, httplib::Response& res) {
    auto body = json::parse(req.body, nullptr, false);
    if (body.is_discarded() || !body.is_object()) {
        json_error(res, 400, "Invalid JSON");
        return std::nullopt;
    }
    return body;
}

// Opaque, stable handle for a browser session in the session list (security
// audit M3). The list used to return an 8-character prefix of the session id
// that DELETE could never match, and the page posted a field that did not
// exist. The handle is derived from the stored (hashed) id, so it is not a
// credential and cannot be turned back into one.
std::string session_handle(const std::string& stored_id) {
    return sha256_hex("bsfchat-session-handle:" + stored_id).substr(0, 32);
}

// Decodes UTF-8 strictly and rejects what has no business in a name that is
// shown to other people and copied into every id_token (security audit L10):
// C0/C1 controls, bidi embeddings/overrides/isolates, zero-width characters
// and tag characters. Returns the offending reason, or nullopt.
std::optional<std::string> display_text_error(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        const auto c = static_cast<unsigned char>(s[i]);
        uint32_t cp = 0;
        size_t len = 0;
        if (c < 0x80) { cp = c; len = 1; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else return "is not valid UTF-8";
        if (i + len > s.size()) return "is not valid UTF-8";
        for (size_t k = 1; k < len; ++k) {
            const auto cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return "is not valid UTF-8";
            cp = (cp << 6) | (cc & 0x3F);
        }
        const bool overlong = (len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) ||
                              (len == 4 && cp < 0x10000);
        if (overlong || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return "is not valid UTF-8";
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return "contains control characters";
        if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x202A && cp <= 0x202E) ||
            (cp >= 0x2060 && cp <= 0x2069) || cp == 0xFEFF || (cp >= 0xE0000 && cp <= 0xE007F)) {
            return "contains invisible or text-direction characters";
        }
        i += len;
    }
    return std::nullopt;
}

bool https_url_acceptable(const std::string& url) {
    if (url.size() > 512 || has_markup_characters(url)) return false;
    if (std::any_of(url.begin(), url.end(),
                    [](unsigned char c) { return c < 0x21 || c >= 0x7f; })) {
        return false;
    }
    auto uri = parse_uri(url);
    return uri.valid && uri.scheme == "https" && !uri.host.empty() && !uri.has_fragment;
}

// Deliberately loose (one '@', something either side, nothing that is not a
// plain printable ASCII character): the address is unverified and used for
// nothing but display, so the point is bounding it, not validating mailboxes.
bool email_acceptable(const std::string& email) {
    if (email.size() > 254 || has_markup_characters(email)) return false;
    if (std::any_of(email.begin(), email.end(),
                    [](unsigned char c) { return c < 0x21 || c >= 0x7f; })) {
        return false;
    }
    auto at = email.find('@');
    return at != std::string::npos && at > 0 && at + 1 < email.size() &&
           email.find('@', at + 1) == std::string::npos;
}

} // namespace

AccountHandler::AccountHandler(IdentityStore& store, const Config& config)
    : store_(store)
    , config_(config)
    , client_address_(config.trusted_proxies)
    , issuer_origin_(uri_origin(parse_uri(config.issuer_url)))
    , login_limiter_(config.login_rate_limit, std::chrono::seconds(config.login_rate_window))
    , login_failures_(config.login_max_failures, std::chrono::seconds(config.login_lockout_seconds))
    // Security audit L6. The per-username lock used to trip at the same
    // threshold as everything else, so anybody who knew a name could lock its
    // owner out with eight bad passwords from one address. Now the tight
    // limit is per (address, name) — a stranger locks out only themselves —
    // and this account-wide limit, four times higher, is the ceiling that
    // still stops a guesser spreading attempts over many addresses. Tripping
    // it now takes at least four addresses (each is capped at
    // login_max_failures by the pair lock and by the request limiter), which
    // is the remaining, documented trade-off.
    , account_failures_(config.login_max_failures * 4, std::chrono::seconds(config.login_lockout_seconds))
    , totp_failures_(config.login_max_failures, std::chrono::seconds(config.login_lockout_seconds)) {}

std::string AccountHandler::client_key(const httplib::Request& req) {
    if (client_address_.looks_like_untrusted_proxy(req)) {
        // Every client of this deployment shares one bucket. Say so, with the
        // fix, at most once a minute.
        const auto now = now_seconds();
        auto last = last_proxy_warning_.load();
        if (now - last >= 60 && last_proxy_warning_.compare_exchange_strong(last, now)) {
            get_logger()->warn(
                "Requests from {} carry X-Forwarded-For, but that network is not in "
                "[auth] trusted_proxies, so the header is ignored and every client behind it is "
                "rate-limited as ONE address. If that is your reverse proxy, add its address to "
                "trusted_proxies.", redact_ip_for_log(req.remote_addr));
        }
    }
    auto addr = client_address_.resolve(req);
    return addr ? *addr : std::string{};
}

bool AccountHandler::reject_unsafe_request(const httplib::Request& req, httplib::Response& res,
                                           bool body_required) {
    if ((body_required || !req.body.empty()) &&
        !is_json_content_type(req.get_header_value("Content-Type"))) {
        json_error(res, 415, "Content-Type must be application/json");
        return false;
    }

    // Sec-Fetch-Site is set by the browser and cannot be forged by page
    // script, so when present it is authoritative; "same-site" is refused
    // too, since nothing on a sibling subdomain has a reason to drive this
    // service's account endpoints. "none" is a user-initiated navigation.
    if (req.has_header("Sec-Fetch-Site")) {
        auto site = req.get_header_value("Sec-Fetch-Site");
        if (site == "cross-site" || site == "same-site") {
            json_error(res, 403, "Cross-site request refused");
            return false;
        }
        return true;
    }
    if (req.has_header("Origin")) {
        auto origin = uri_origin(parse_uri(req.get_header_value("Origin")));
        if (origin.empty() || origin != issuer_origin_) {
            json_error(res, 403, "Cross-site request refused");
            return false;
        }
    }
    return true;
}

std::string AccountHandler::session_cookie(const std::string& session_id, int max_age_seconds) const {
    std::string cookie = "session=" + session_id + "; Path=/; HttpOnly; SameSite=Lax; Max-Age="
                       + std::to_string(max_age_seconds);
    if (config_.cookie_secure) cookie += "; Secure";
    return cookie;
}

void AccountHandler::prune_limiters() {
    login_limiter_.prune();
    login_failures_.prune();
    account_failures_.prune();
    totp_failures_.prune();
}

const std::string& AccountHandler::dummy_password_hash() {
    std::call_once(dummy_hash_once_, [this] {
        dummy_hash_ = hash_password(secure_random_hex(16), config_.password_hash_iterations);
    });
    return dummy_hash_;
}

void AccountHandler::start_session(const Account& account, httplib::Response& res, int status) {
    auto now = now_seconds();
    auto session_id = generate_session_id();
    Session session;
    session.session_id = session_id;
    session.account_id = account.id;
    session.created_at = now;
    session.expires_at = now + kSessionLifetimeSeconds;
    if (!store_.create_session(session)) {
        json_error(res, 500, "Failed to create session");
        return;
    }

    json response = {
        {"user_id", account.id},
        {"username", account.username},
        {"session_id", session_id}
    };
    res.set_header("Set-Cookie", session_cookie(session_id, kSessionLifetimeSeconds));
    res.status = status;
    res.set_content(response.dump(), "application/json");
}

std::string AccountHandler::get_session_account(const httplib::Request& req) {
    // Both lookups filter out disabled accounts in SQL (security audit H1).

    // Browser session cookie.
    auto session_id = extract_session_id(req);
    if (!session_id.empty()) {
        auto session = store_.get_browser_session(session_id);
        if (session && session->expires_at > now_seconds()) {
            return session->account_id;
        }
    }

    // A browser session id may also be presented as a bearer token: /api/login
    // returns it in the JSON body precisely so non-browser callers can use it.
    // get_browser_session() filters on token_type, so an OIDC access token
    // presented here resolves to nothing.
    auto token = extract_bearer_token(req);
    if (!token.empty()) {
        auto session = store_.get_browser_session(token);
        if (session && session->expires_at > now_seconds()) {
            return session->account_id;
        }
    }

    return "";
}

AuthContext AccountHandler::authenticate(const httplib::Request& req, const std::string& required_scope) {
    AuthContext ctx;

    auto browser_account = get_session_account(req);
    if (!browser_account.empty()) {
        ctx.account_id = browser_account;
        ctx.token_type = token_type::kBrowserSession;
        ctx.credential_id = extract_session_id(req);
        if (ctx.credential_id.empty()) ctx.credential_id = extract_bearer_token(req);
        return ctx;
    }

    auto token = extract_bearer_token(req);
    if (!token.empty()) {
        auto access = store_.get_oidc_access_token(token);
        if (access && access->expires_at > now_seconds() &&
            scope_contains(access->scope, required_scope)) {
            ctx.account_id = access->account_id;
            ctx.token_type = token_type::kOidcAccess;
            ctx.credential_id = token;
            ctx.scope = access->scope;
            ctx.client_id = access->client_id;
        }
    }

    return ctx;
}

void AccountHandler::handle_register(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    if (!config_.registration_enabled) {
        json_error(res, 403, "Registration is disabled");
        return;
    }

    // Registration sets the session cookie too, so it is a login-CSRF target
    // exactly like /api/login.
    if (!reject_unsafe_request(req, res)) return;

    // Registration runs a full-cost PBKDF2, so an unauthenticated flood here is
    // a CPU exhaustion vector as well as an account-spam one.
    auto ip_key = client_key(req);
    if (!ip_key.empty() && !login_limiter_.allow("register:" + ip_key)) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many registration attempts, please slow down");
        return;
    }

    auto body = parse_object(req, res);
    if (!body) return;

    auto username = string_field(*body, "username");
    auto password = string_field(*body, "password");
    auto email = string_field(*body, "email");

    if (username.empty() || password.empty()) {
        json_error(res, 400, "Username and password are required");
        return;
    }

    if (auto err = username_policy_error(username)) {
        json_error(res, 400, *err);
        return;
    }

    if (password.size() < 8) {
        json_error(res, 400, "Password must be at least 8 characters");
        return;
    }
    if (password.size() > kMaxPasswordLength) {
        json_error(res, 400, "Password is too long");
        return;
    }

    if (!email.empty() && !email_acceptable(email)) {
        json_error(res, 400, "Email address is not valid");
        return;
    }

    // Check for existing user
    if (store_.get_account_by_username(username)) {
        json_error(res, 409, "Username already taken");
        return;
    }

    // Lookalikes of an existing name (`a1ice`, `a.lice` beside `alice`).
    // Checked after the exact match so a taken name still says "taken"; the
    // message does not name the account it resembles. Same as the chat server.
    if (store_.find_account_by_username_skeleton(username_skeleton(username))) {
        json_error(res, 409,
                   "That username is too similar to an existing account. Choose one that differs "
                   "by more than punctuation or lookalike characters.");
        return;
    }

    // A taken email used to fall through to the INSERT, fail the UNIQUE
    // constraint and come back as a 500. Refused explicitly now. This still
    // tells a prober that the address has an account (security audit L2);
    // closing that needs email verification or dropping the uniqueness of an
    // address nobody has verified, both larger changes than this fix.
    if (store_.email_in_use(email)) {
        json_error(res, 409, "That email address cannot be used for a new account");
        return;
    }

    auto now = now_seconds();
    Account account;
    account.id = generate_uuid();
    account.username = username;
    account.email = email;
    account.password_hash = hash_password(password, config_.password_hash_iterations);
    account.display_name = username;
    account.created_at = now;
    account.updated_at = now;

    if (!store_.create_account(account)) {
        // Lost a race with a concurrent registration of the same name/email.
        json_error(res, 409, "Username or email address already in use");
        return;
    }

    // The username has passed username_policy_error(), so it is plain ASCII
    // and cannot forge a log line.
    log->info("Account created: {} ({})", username, account.id);

    start_session(account, res, 201);
}

void AccountHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    if (!reject_unsafe_request(req, res)) return;

    // Throttle before doing any work, so an unauthenticated caller cannot
    // spend our CPU on PBKDF2 or enumerate accounts at speed.
    auto ip_key = client_key(req);
    if (!ip_key.empty() && !login_limiter_.allow("login:" + ip_key)) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many login attempts, please slow down");
        return;
    }

    auto body = parse_object(req, res);
    if (!body) return;

    auto username = string_field(*body, "username");
    auto password = string_field(*body, "password");

    if (username.empty() || password.empty()) {
        json_error(res, 400, "Username and password are required");
        return;
    }

    // Failure keys use the username as SUBMITTED, never whether it exists,
    // so the lockout is not an existence oracle. They are never logged.
    //
    // There is no per-address lockout any more (security audit H2): behind a
    // proxy that is not in trusted_proxies every user shares one address, and
    // eight bad logins from anyone locked the whole platform out. Per-address
    // VOLUME is still bounded by login_limiter_ above.
    const auto pair_key = ip_key.empty() ? std::string{} : "login:" + ip_key + "|" + username;
    const auto name_key = "login-user:" + username;

    auto account = store_.get_account_by_username(username);

    // A second factor under attack locks its account for everybody, the
    // owner included (security audit M2). Only somebody holding the password
    // can cause this, so it is not a stranger's lockout. Checked before the
    // password so that a locked account's login answer does not become a
    // password oracle.
    const bool second_factor_locked = account && totp_failures_.is_locked("2fa-user:" + account->id);

    if ((!pair_key.empty() && login_failures_.is_locked(pair_key)) ||
        account_failures_.is_locked(name_key) || second_factor_locked) {
        int64_t retry = account_failures_.retry_after(name_key);
        if (!pair_key.empty()) retry = std::max(retry, login_failures_.retry_after(pair_key));
        if (account) retry = std::max(retry, totp_failures_.retry_after("2fa-user:" + account->id));
        res.set_header("Retry-After", std::to_string(retry));
        // One message for every cause: naming which lock fired would tell a
        // sprayer which usernames other people are attacking.
        json_error(res, 429, "Too many failed attempts, try again later");
        return;
    }

    // Exactly one PBKDF2 whatever the outcome: an unknown username used to
    // return before any hashing, 600k iterations faster than a wrong password,
    // which enumerated usernames by timing (security audit L2).
    bool ok = false;
    if (account && !account->password_hash.empty()) {
        ok = verify_password(password, account->password_hash);
    } else {
        verify_password(password, dummy_password_hash());
    }
    // A disabled account answers exactly like a wrong password, so disabling
    // does not confirm the password to whoever is trying it (H1).
    if (ok && account->disabled()) ok = false;

    if (!ok) {
        if (!pair_key.empty() && login_failures_.record_failure(pair_key)) {
            log->warn("Login lockout engaged for a username from {}", redact_ip_for_log(ip_key));
        }
        if (account_failures_.record_failure(name_key)) {
            log->warn("Account-wide login lockout engaged{}",
                      account ? " for account " + account->id : std::string(" for an unknown username"));
        }
        // No username in the log (security audit L8): it is arbitrary bytes
        // from an unauthenticated request, it can forge log lines, and it is
        // where people type their password by mistake.
        log->warn("Failed login from {}{}", redact_ip_for_log(ip_key),
                  account ? " for account " + account->id : std::string());
        json_error(res, 401, "Invalid username or password");
        return;
    }

    if (!pair_key.empty()) login_failures_.clear(pair_key);
    account_failures_.clear(name_key);

    // Opportunistically upgrade hashes written under the old 4,096-iteration
    // scheme, now that we hold the plaintext and know it is correct.
    if (password_needs_rehash(account->password_hash, config_.password_hash_iterations)) {
        try {
            store_.update_password_hash(account->id, hash_password(password, config_.password_hash_iterations));
            log->info("Upgraded password hash for account {}", account->id);
        } catch (const std::exception& e) {
            log->warn("Password hash upgrade failed for account {}: {}", account->id, e.what());
        }
    }

    // Check if 2FA is enabled
    auto totp_info = store_.get_totp(account->id);
    if (totp_info && totp_info->enabled) {
        auto login_token = generate_hex_token(32);
        auto now = now_seconds();
        store_.create_login_token(login_token, account->id, now + 300); // 5 minutes

        log->info("Login requires 2FA: account {}", account->id);

        json response = {
            {"requires_2fa", true},
            {"login_token", login_token}
        };
        res.set_content(response.dump(), "application/json");
        return;
    }

    log->info("Login successful: account {}", account->id);
    start_session(*account, res);
}

void AccountHandler::handle_logout(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res, /*body_required=*/false)) return;

    // Whichever browser session credential was presented.
    auto session_id = extract_session_id(req);
    if (session_id.empty()) session_id = extract_bearer_token(req);

    // Plain logout ends THIS browser session only. It deliberately does not
    // end the user's other devices or the desktop client's refresh token:
    // signing out of the portal on a shared computer is the common case, and
    // logging the user's own desktop client out every time they do it would
    // teach people not to sign out. Ending everything is an explicit choice,
    // {"everywhere": true}, offered as "Sign out everywhere" in the portal
    // (security audit H4).
    auto body = json::parse(req.body, nullptr, false);
    const bool everywhere = body.is_object() && body.contains("everywhere") &&
                            body["everywhere"].is_boolean() && body["everywhere"].get<bool>();
    int ended = 0;
    if (everywhere) {
        ended = store_.revoke_account_credentials(account_id);
        get_logger()->info("Signed out everywhere: account {} ({} session(s)/app(s) ended)",
                           account_id, ended);
    } else if (!session_id.empty()) {
        auto session = store_.get_browser_session(session_id);
        if (session) store_.delete_session(session_id);
    }

    res.set_header("Set-Cookie", session_cookie("", 0));
    res.set_content(json{{"success", true}, {"ended", ended}}.dump(), "application/json");
}

void AccountHandler::handle_get_profile(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    json response = {
        {"user_id", account->id},
        {"username", account->username},
        {"display_name", account->display_name},
        {"avatar_url", account->avatar_url},
        {"email", account->email},
        {"is_admin", account->is_admin}
    };
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_update_profile(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res)) return;

    auto body = parse_object(req, res);
    if (!body) return;

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    // Every field is type-checked and bounded (security audit L10). These
    // values go into every id_token and from there into chat servers' member
    // lists, so a megabyte name or a bidi override here is everybody's problem.
    const auto string_member = [&](const char* key, std::string& out) {
        if (!body->contains(key)) return true;
        const auto& v = (*body)[key];
        if (!v.is_string()) {
            json_error(res, 400, std::string(key) + " must be a string");
            return false;
        }
        out = v.get<std::string>();
        return true;
    };
    auto display_name = account->display_name;
    auto avatar_url = account->avatar_url;
    auto email = account->email;
    if (!string_member("display_name", display_name) || !string_member("avatar_url", avatar_url) ||
        !string_member("email", email)) {
        return;
    }
    if (display_name.size() > 128) {
        json_error(res, 400, "Display name is too long");
        return;
    }
    if (auto err = display_text_error(display_name)) {
        json_error(res, 400, "Display name " + *err);
        return;
    }
    if (!avatar_url.empty() && !https_url_acceptable(avatar_url)) {
        json_error(res, 400, "Avatar URL must be an https:// URL of at most 512 characters");
        return;
    }
    if (!email.empty() && !email_acceptable(email)) {
        json_error(res, 400, "Email address is not valid");
        return;
    }
    // A taken address used to fail the UNIQUE constraint silently while the
    // handler answered 200 with the new value (security audit L2).
    if (email != account->email && store_.email_in_use(email, account->id)) {
        json_error(res, 409, "That email address cannot be used");
        return;
    }

    // Handle password change
    int signed_out = -1;
    if (body->contains("new_password")) {
        auto old_password = string_field(*body, "old_password");
        if (old_password.empty() || !verify_password(old_password, account->password_hash)) {
            json_error(res, 403, "Current password is incorrect");
            return;
        }
        auto new_password = string_field(*body, "new_password");
        if (new_password.size() < 8) {
            json_error(res, 400, "New password must be at least 8 characters");
            return;
        }
        if (new_password.size() > kMaxPasswordLength) {
            json_error(res, 400, "New password is too long");
            return;
        }
        // update_account() does not write password_hash, so the change has to
        // go through the dedicated statement — previously it was silently
        // discarded and the old password kept working.
        auto new_hash = hash_password(new_password, config_.password_hash_iterations);
        if (!store_.update_password_hash(account->id, new_hash)) {
            json_error(res, 500, "Failed to update password");
            return;
        }
        account->password_hash = new_hash;

        // A password change is what a user does when they think someone else
        // is in their account, and it used to evict nobody (security audit
        // H4). Every other browser session, every access token and every
        // refresh token ends here — including the user's own desktop client,
        // which signs in again. The session making the change survives: it
        // just proved the old password, and signing it out would only make the
        // person securing the account start over.
        auto current = extract_session_id(req);
        if (current.empty()) current = extract_bearer_token(req);
        signed_out = store_.revoke_account_credentials(account->id, current);
        log->info("Password changed for account {}; {} other session(s)/app(s) ended",
                  account->id, signed_out);
    }

    account->display_name = display_name;
    account->avatar_url = avatar_url;
    account->email = email;
    account->updated_at = now_seconds();
    if (!store_.update_account(*account)) {
        json_error(res, 409, "Profile could not be saved");
        return;
    }

    json response = {
        {"user_id", account->id},
        {"username", account->username},
        {"display_name", account->display_name},
        {"avatar_url", account->avatar_url},
        {"email", account->email}
    };
    if (signed_out >= 0) response["signed_out_elsewhere"] = signed_out;
    res.set_content(response.dump(), "application/json");
}

// Session management

void AccountHandler::handle_list_sessions(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    // Rows carry the stored hash, so the presented credential is hashed to
    // find "this one".
    auto current = extract_session_id(req);
    if (current.empty()) current = extract_bearer_token(req);
    const auto current_hash = hash_token(current);
    auto sessions = store_.list_sessions_for_account(account_id);

    json result = json::array();
    for (const auto& s : sessions) {
        result.push_back({
            {"session_id", session_handle(s.session_id)},
            {"created_at", s.created_at},
            {"expires_at", s.expires_at},
            {"is_current", s.session_id == current_hash}
        });
    }
    res.set_content(result.dump(), "application/json");
}

void AccountHandler::handle_revoke_session(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res, /*body_required=*/false)) return;

    // Path: /api/user/sessions/<handle>, as returned by handle_list_sessions.
    auto handle = req.matches.size() > 1 ? req.matches[1].str() : std::string{};
    if (handle.empty()) {
        json_error(res, 400, "Session ID required");
        return;
    }

    auto current = extract_session_id(req);
    if (current.empty()) current = extract_bearer_token(req);
    const auto current_hash = hash_token(current);

    // Resolved within the caller's own sessions, so a handle can never reach
    // another account's session.
    for (const auto& s : store_.list_sessions_for_account(account_id)) {
        if (!constant_time_equals(session_handle(s.session_id), handle)) continue;
        if (s.session_id == current_hash) {
            json_error(res, 400, "Cannot revoke current session");
            return;
        }
        store_.delete_stored_session(account_id, s.session_id);
        res.set_content(json{{"success", true}}.dump(), "application/json");
        return;
    }
    json_error(res, 404, "Session not found");
}

void AccountHandler::handle_list_apps(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    json result = json::array();
    for (const auto& rt : store_.list_refresh_tokens_for_account(account_id)) {
        auto client = store_.get_oauth_client(rt.client_id);
        result.push_back({
            {"id", rt.family_id},
            {"client_id", rt.client_id},
            {"client_name", client ? client->name : rt.client_id},
            {"scope", rt.scope},
            {"created_at", rt.created_at},
            {"expires_at", rt.expires_at},
            {"absolute_expires_at", rt.family_expires_at}
        });
    }
    res.set_content(result.dump(), "application/json");
}

void AccountHandler::handle_revoke_app(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res, /*body_required=*/false)) return;

    auto family_id = req.matches.size() > 1 ? req.matches[1].str() : std::string{};
    // Scoped to the caller's account in SQL.
    if (!store_.delete_refresh_family(account_id, family_id)) {
        json_error(res, 404, "App not found");
        return;
    }
    res.set_content(json{{"success", true}}.dump(), "application/json");
}

// 2FA / TOTP

void AccountHandler::handle_2fa_status(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }

    auto totp = store_.get_totp(account_id);
    bool enabled = totp && totp->enabled;
    res.set_content(json{{"enabled", enabled}}.dump(), "application/json");
}

void AccountHandler::handle_2fa_setup(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res, /*body_required=*/false)) return;

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    // Re-running setup on an account that already has 2FA is a downgrade, not
    // an enrolment: set_totp_secret() does INSERT OR REPLACE with enabled = 0,
    // so a single POST here silently stripped the second factor and left a new
    // unconfirmed secret behind. This endpoint only needs a session cookie,
    // while /2fa/disable deliberately demands the password — so the cheap path
    // to single-factor was the one with no password on it. Turning 2FA off is
    // /2fa/disable's job, and it asks.
    if (auto existing = store_.get_totp(account_id); existing && existing->enabled) {
        json_error(res, 409,
                   "Two-factor authentication is already enabled. Disable it first.");
        return;
    }

    auto secret = bsfchat::generate_totp_secret();
    auto backup_codes = bsfchat::generate_backup_codes(8);
    auto uri = bsfchat::totp_provisioning_uri(secret, account->username, "BSFChat");

    // The store hashes the codes on the way in; this response is the only time
    // they are ever visible.
    store_.set_totp_secret(account_id, secret, backup_codes);

    json response = {
        {"secret", secret},
        {"provisioning_uri", uri},
        {"backup_codes", backup_codes}
    };
    res.set_content(response.dump(), "application/json");
}

void AccountHandler::handle_2fa_verify(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res)) return;

    auto body = parse_object(req, res);
    if (!body) return;

    auto code = string_field(*body, "code");
    if (code.empty()) {
        json_error(res, 400, "Code is required");
        return;
    }

    // Enrolment confirmation is authenticated, but still guessable at 10^6, so
    // it gets the same throttling as the login-time check.
    const auto enrol_key = "2fa-enrol:" + account_id;
    if (totp_failures_.is_locked(enrol_key)) {
        res.set_header("Retry-After", std::to_string(totp_failures_.retry_after(enrol_key)));
        json_error(res, 429, "Too many incorrect codes, try again later");
        return;
    }

    auto totp = store_.get_totp(account_id);
    if (!totp) {
        json_error(res, 400, "2FA not set up - call setup first");
        return;
    }

    // The confirming code's step is recorded, so it cannot then be replayed
    // at the login prompt.
    auto step = bsfchat::verify_totp_step(totp->secret, code);
    if (!step || !store_.accept_totp_step(account_id, *step)) {
        totp_failures_.record_failure(enrol_key);
        json_error(res, 400, "Invalid code");
        return;
    }

    totp_failures_.clear(enrol_key);
    store_.enable_totp(account_id);

    // Turning on a second factor is a "secure my account" action, so whoever
    // was already signed in with the password alone is signed out (H4).
    auto current = extract_session_id(req);
    if (current.empty()) current = extract_bearer_token(req);
    auto ended = store_.revoke_account_credentials(account_id, current);
    res.set_content(json{{"success", true}, {"signed_out_elsewhere", ended}}.dump(), "application/json");
}

void AccountHandler::handle_2fa_disable(const httplib::Request& req, httplib::Response& res) {
    auto account_id = get_session_account(req);
    if (account_id.empty()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!reject_unsafe_request(req, res)) return;

    auto body = parse_object(req, res);
    if (!body) return;

    auto password = string_field(*body, "password");
    if (password.empty()) {
        json_error(res, 400, "Password is required");
        return;
    }

    auto account = store_.get_account_by_id(account_id);
    if (!account) {
        json_error(res, 404, "Account not found");
        return;
    }

    if (!verify_password(password, account->password_hash)) {
        json_error(res, 403, "Invalid password");
        return;
    }

    store_.disable_totp(account_id);

    // Same reasoning as a password change: a security setting changed, so
    // nothing else stays signed in on the strength of the old one.
    auto current = extract_session_id(req);
    if (current.empty()) current = extract_bearer_token(req);
    auto ended = store_.revoke_account_credentials(account_id, current);
    res.set_content(json{{"success", true}, {"signed_out_elsewhere", ended}}.dump(), "application/json");
}

void AccountHandler::handle_login_2fa(const httplib::Request& req, httplib::Response& res) {
    auto log = get_logger();

    if (!reject_unsafe_request(req, res)) return;

    auto ip_key = client_key(req);
    if (!ip_key.empty() && !login_limiter_.allow("2fa:" + ip_key)) {
        res.set_header("Retry-After", std::to_string(config_.login_rate_window));
        json_error(res, 429, "Too many attempts, please slow down");
        return;
    }

    auto body = parse_object(req, res);
    if (!body) return;

    auto login_token = string_field(*body, "login_token");
    auto code = string_field(*body, "code");

    if (login_token.empty() || code.empty()) {
        json_error(res, 400, "login_token and code are required");
        return;
    }

    // The per-address 2FA lockout is gone for the same reason as the login
    // one (security audit H2); the limit that matters is per ACCOUNT, below.
    // A login token is 256 bits, so guessing tokens is not a strategy.
    auto account_id = store_.validate_login_token(login_token);
    if (!account_id) {
        json_error(res, 401, "Invalid or expired login token");
        return;
    }

    // Security audit M2: the login token burns after totp_max_attempts, but a
    // password holder could simply ask for another one from another address.
    // Wrong codes now count against the account, and once it is locked no
    // code is accepted and handle_login issues no new login token.
    const auto account_key = "2fa-user:" + *account_id;
    if (totp_failures_.is_locked(account_key)) {
        store_.delete_login_token(login_token);
        res.set_header("Retry-After", std::to_string(totp_failures_.retry_after(account_key)));
        json_error(res, 429, "Too many incorrect codes, try again later");
        return;
    }

    auto totp = store_.get_totp(*account_id);
    if (!totp || !totp->enabled) {
        json_error(res, 400, "2FA not enabled for this account");
        return;
    }

    // TOTP first, then a backup code. A TOTP code is accepted only if its
    // time-step is later than the last one this account used, so a captured
    // code cannot be replayed within its ~90 s window (security audit M2).
    bool code_valid = false;
    if (auto step = bsfchat::verify_totp_step(totp->secret, code)) {
        code_valid = store_.accept_totp_step(*account_id, *step);
    } else {
        code_valid = store_.consume_backup_code(*account_id, code);
    }
    if (!code_valid) {
        if (totp_failures_.record_failure(account_key)) {
            log->warn("Second-factor lockout engaged for account {} (from {})", *account_id,
                      redact_ip_for_log(ip_key));
        }
        // Burn the login token after a handful of wrong codes. Without this the
        // token stayed usable for its full five minutes, which is more than
        // enough to walk the entire six-digit keyspace in parallel.
        bool destroyed = store_.record_login_token_failure(login_token, config_.totp_max_attempts);
        if (destroyed) {
            log->warn("2FA login token destroyed after {} failed codes (account {}, from {})",
                      config_.totp_max_attempts, *account_id, redact_ip_for_log(ip_key));
            json_error(res, 401, "Too many incorrect codes — please sign in again");
            return;
        }
        json_error(res, 401, "Invalid 2FA code");
        return;
    }

    totp_failures_.clear(account_key);

    // Consume the login token
    store_.delete_login_token(login_token);

    auto account = store_.get_account_by_id(*account_id);
    if (!account || account->disabled()) {
        json_error(res, 401, "Invalid or expired login token");
        return;
    }
    log->info("Login 2FA successful: account {}", account->id);

    start_session(*account, res);
}

// Server memberships
//
// These are the one API family an OIDC access token may reach, because the
// desktop client legitimately syncs the user's server list with the token it
// receives from the OIDC flow. Everything else on this handler stays behind a
// browser session.

void AccountHandler::handle_list_servers(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!may_use_server_list(ctx)) {
        json_error(res, 403, "This client may not access the server list");
        return;
    }
    const auto& account_id = ctx.account_id;

    auto servers = store_.list_server_memberships(account_id);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : servers) {
        arr.push_back({
            {"id", s.id},
            {"server_url", s.server_url},
            {"server_name", s.server_name},
            {"joined_at", s.joined_at}
        });
    }
    res.set_content(arr.dump(), "application/json");
}

void AccountHandler::handle_add_server(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!may_use_server_list(ctx)) {
        json_error(res, 403, "This client may not access the server list");
        return;
    }
    const auto& account_id = ctx.account_id;

    auto body = nlohmann::json::parse(req.body, nullptr, false);
    // .contains() does not type-check: body["server_url"].get<std::string>()
    // on {"server_url": 1} threw json::type_error, which httplib turned into
    // a 500 rather than a 400.
    if (body.is_discarded() || !body.contains("server_url")
        || !body["server_url"].is_string()) {
        json_error(res, 400, "Missing server_url");
        return;
    }

    std::string url = body["server_url"].get<std::string>();
    std::string why;
    if (!server_url_acceptable(url, why)) {
        json_error(res, 400, why);
        return;
    }

    std::string name;
    if (body.contains("server_name") && body["server_name"].is_string()) {
        name = body["server_name"].get<std::string>();
        if (name.size() > kMaxServerNameLength) name.resize(kMaxServerNameLength);
    }

    // The list is a convenience sync, not storage. Without a cap a single
    // "openid"-scoped token could grow it without limit.
    if (store_.list_server_memberships(account_id).size() >= kMaxServerMemberships) {
        json_error(res, 409, "Too many servers on this account");
        return;
    }

    store_.add_server_membership(account_id, url, name);
    res.set_content(nlohmann::json{{"success", true}}.dump(), "application/json");
}

void AccountHandler::handle_remove_server(const httplib::Request& req, httplib::Response& res) {
    auto ctx = authenticate(req, kServersScope);
    if (!ctx.authenticated()) {
        json_error(res, 401, "Not authenticated");
        return;
    }
    if (!may_use_server_list(ctx)) {
        json_error(res, 403, "This client may not access the server list");
        return;
    }
    const auto& account_id = ctx.account_id;

    // Accept server_url from query param (for DELETE which may not carry body)
    // or from JSON body.
    std::string url;
    if (req.has_param("server_url")) {
        url = req.get_param_value("server_url");
    } else {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (!body.is_discarded() && body.contains("server_url")
            && body["server_url"].is_string()) {
            url = body["server_url"].get<std::string>();
        }
    }
    if (url.empty()) {
        json_error(res, 400, "Missing server_url");
        return;
    }

    store_.remove_server_membership(account_id, url);
    res.set_content(nlohmann::json{{"success", true}}.dump(), "application/json");
}

} // namespace bsfchat::id
