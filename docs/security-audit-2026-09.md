# BSFChat identity service — security audit, September 2026

Audited revision: `origin/main` at `a6b6f6b` (Merge branch 'fix/bughunt').
Cross-referenced: `protocol` `3fd3f23`, `server` `ed7bd1d`, `client` and `deploy`
`origin/main` as of 2026-09-22.
Branch: `audit/security-2026-09` (worktree `wt/identity-audit`). Not pushed.

Nothing was fixed. One finding (C1) is critical, but it cannot be fixed inside
this repository alone without breaking every sign-in. The section on C1
explains why, and what to do tonight instead.

## How to read this

Every finding says whether it is **proven** or **reasoned**:

* **Proven** means there is a test in `tests/test_security_audit.cpp` that
  asserts the correct behaviour and **fails** on the audited revision. The
  failure is the proof. The tests are built as a separate executable,
  `identity_security_audit_tests`, which is deliberately not registered with
  ctest, so the regular suite and CI stay green. Run it with
  `./build/tests/identity_security_audit_tests`. On `a6b6f6b`, all 13 tests fail,
  each for the reason its comment gives. When a finding is fixed, its test
  starts passing and can move into `test_auth_flows.cpp`.
* **Reasoned** means the conclusion comes from reading code, with file:line
  references. No test proves it.

## Attack surface

| Surface | What it is |
| --- | --- |
| HTTP | `src/http/HttpServer.cpp` is a 28-line wrapper around **cpp-httplib v0.47.0**. It is not a hand-rolled parser. The parsing surface is httplib's, used with its defaults: 8 KiB URI and header lines, 100 headers, 100 MB body, 5 s read timeout, a thread pool of max(8, cores-1) that grows to 4× that. In the shipped deployment it sits behind nginx on `127.0.0.1:8480`. |
| OIDC | `GET /authorize`, `POST /authorize/decision` (consent), `POST /token` (authorization_code, refresh_token), `GET /userinfo`, `GET /jwks`, `POST /token/revoke`, discovery. There is one built-in public client, `bsfchat-desktop`, with loopback redirects and PKCE. |
| Accounts | `/register`, `/api/login`, `/api/login/2fa`, `/api/logout`, `/api/profile` (GET/PUT, including password change), `/api/user/sessions`, `/api/user/2fa/*`, and `/api/servers` (the one API family an OIDC access token can reach). |
| Admin | `/api/admin/users`, `/api/admin/users/{id}/disable`, and `/api/admin/clients` (GET/POST). |
| Static web | `web/` served by the httplib mount point: the login, register, profile and admin pages. |
| Trust boundary | The chat server accepts this service's id_token as a sign-in credential (`m.login.token`). Since this week it also accepts it as proof of identity for **permanently linking** that identity to an existing account (`server/src/api/AuthHandler.cpp:1187`, `docs/account-linking.md`). |

## Summary

| ID | Severity | Finding | Proof |
| --- | --- | --- | --- |
| C1 | **Critical** | An id_token is accepted at every chat server. A hostile server can sign in as its users anywhere, and can permanently hijack their sign-in through `link_identity`. | Proven (identity side); chain reasoned |
| H1 | High | Admin "disable user" leaves sessions, access tokens and refresh tokens working. The refresh token keeps minting id_tokens. | Proven |
| H2 | High | Rate limits and lockouts are keyed on the TCP peer, which behind the shipped nginx is one address for everybody. Eight bad logins lock the whole platform out of sign-in for 15 minutes. | Proven (handler); deployment reasoned |
| H3 | High | Login CSRF: a text/plain form posts JSON to `/api/login`. Combined with unrestricted usernames, the victim is silently signed in to a lookalike attacker account. | Proven (server half); browser half reasoned |
| H4 | High | A password change or logout revokes nothing. Refresh tokens are effectively permanent, the user cannot see them, and the user cannot revoke them. | Proven |
| M1 | Medium | Stored XSS in `profile.html` through `server_url`, writable with any `openid` access token. | Proven (server half); DOM half reasoned |
| M2 | Medium | A TOTP code can be replayed, and there is no per-account limit on second-factor guesses. | Proven |
| M3 | Medium | Session revocation cannot work: the list returns an 8-character prefix and DELETE needs the full id. | Proven |
| M4 | Medium | The id_token carries the email address whatever scope was granted. Every chat server operator receives it. | Proven |
| M5 | Medium | Any relying party's `openid` access token can rewrite the list of servers the desktop client auto-connects to. | Reasoned |
| L1–L10 | Low | See below. | Mixed |

---

## C1 — Critical — an id_token signs its holder in to every chat server

**Proof status:** the identity side is proven by
`SecurityAudit.C1_IdTokenAudienceIsBoundToTheChatServer`. That test obtains an
id_token while asking for `resource=https://evil-chat.example`, then runs
exactly the verification the chat server runs (`jwt_verify(token, key, iss,
"bsfchat-desktop")`). Verification succeeds, with `aud="bsfchat-desktop"`. The
chain on the server and client side is reasoned from code cited below.

**Attacker story.** Mallory runs a BSFChat server, `evil.example`. It
advertises `https://id.bsfchat.com` as its identity provider in its login flows
(`client/src/net/ServerDiscovery.cpp`), as any server trusting the official
provider does. Alice adds it and signs in with her BSFChat ID. Her client
completes the PKCE flow with `client_id=bsfchat-desktop` and POSTs the id_token
to `evil.example` (`client/src/net/ServerConnection.cpp:1039-1042`). Mallory
now holds a token with `iss=https://id.bsfchat.com` and `aud=bsfchat-desktop`.
It is valid for an hour, plus the chat server's 60 s leeway. Mallory can then:

1. POST it to `chat.bsfchat.com` as `m.login.token` and get a session as
   Alice, or as whatever account Alice has linked her identity to (the owner's
   `@josh`, with `admin`, is the documented migration target).
2. Worse, POST it to `chat.bsfchat.com`'s
   `/account/link_identity` together with a token for Mallory's own account
   there. The server checks the bearer (Mallory's account, which is valid) and
   the id_token (valid). It links Alice's identity to **Mallory's** account and
   revokes every session of Alice's existing `@oidc_…` account
   (`AuthHandler.cpp:1307`). From then on, every "Sign in with BSFChat ID" that
   Alice makes on `chat.bsfchat.com` lands in Mallory's account. A link is
   insert-only, and there is no unlink (`docs/account-linking.md`, *Deferred*).
   This is permanent until an operator edits the database.

Mallory does not even need Alice to add the server by hand. See M5 and M1: any
relying party holding Alice's `openid` access token can write `evil.example`
into the server list that her client auto-connects to
(`client/src/net/ServerManager.cpp:745`).

**Cause.**

* `OidcHandler::create_id_token` (`src/api/OidcHandler.cpp:822-835`) sets
  `aud` to the OAuth client (`bsfchat-desktop`), never to the chat server the
  user is signing in to. There is no request parameter that can narrow it:
  `resource` (RFC 8707) and `audience` are ignored in `handle_authorize`
  (`:188-310`).
* The chat servers are not OAuth clients of this provider. They are bearer
  recipients of a token minted for somebody else (the desktop app), and they all
  check the same `aud` (`server/src/core/Config.h:29`, default
  `client_id = "bsfchat-desktop"`).
* There is no `nonce` either (L1). A nonce alone would not fix this, though: a
  relaying server can obtain a nonce from the victim server and pass it through.

**Impact.** Anyone who runs a chat server can impersonate that server's users
on every other server that trusts the same provider, and can take over their
sign-in route there permanently. A flaw in who can sign in as whom is exactly
what this audit was asked to find, and this is the largest one.

**Why this was not fixed tonight.** The fix changes the token contract in three
repositories at once. The client must say which server it is signing in to, the
provider must put that server into `aud`, and the server must check `aud`
against its own public URL. An identity-only change either does nothing, or
(if it changed `aud`) breaks every existing sign-in. It cannot be made safely
in one night in one repo.

**Do tonight (operational, no code):**

* Do **not** deploy `server`'s `link_identity` to production until this is
  fixed. It turns a one-hour replay into a permanent, irreversible hijack. If
  it is already deployed, consider disabling the route.
* Treat any chat server run by someone other than the operator of
  `id.bsfchat.com` as able to impersonate its users elsewhere.

**Recommended fix:**

1. Client: send `resource=<chat server base URL>` (RFC 8707) on `/authorize`
   and `/token`. The client knows which server it is talking to. A relaying
   server cannot change that.
2. Identity: accept one absolute https (or loopback) `resource`, bind it to the
   authorization code, and issue the id_token with `aud=[resource]`, `azp=client_id`.
   Show the server's host on the consent page ("Sign in to
   **chat.example**"). Shorten the id_token lifetime to about 5 minutes.
   The token is used once, at sign-in.
3. Server: require `aud` to contain its own configured public base URL, and
   reject tokens whose only audience is `bsfchat-desktop` after a transition
   window. Record each id_token's `jti` (with `iat`/`exp`) and refuse reuse.
4. Until (3) ships everywhere, the identity side can offer both forms: `aud`
   as `[resource, "bsfchat-desktop"]`. Old servers keep working and new
   servers get the binding.

---

## H1 — High — "disable user" does not disable a signed-in user

**Proof:** `SecurityAudit.H1_DisabledAccountCannotKeepMintingIdTokens` (fails 3
ways).

**Attacker story.** An account is compromised and the admin clicks Disable.
The attacker, who already has the browser session and the desktop client's
refresh token, keeps going. `/token` with `grant_type=refresh_token` returns a
fresh id_token, which signs in to every chat server (C1 multiplies this). The
refresh token rotates, so the 30-day expiry never arrives. The browser session
keeps working for up to 7 days and can start new authorizations.

**Cause.** `IdentityStore::disable_account` (`src/store/IdentityStore.cpp:424-433`)
only blanks `password_hash`. Nothing deletes sessions, access tokens or refresh
tokens, and nothing on the token, refresh, authorize or session paths checks a
disabled state. None exists: there is no `disabled` column. There is also no
re-enable, and the admin UI cannot see who is disabled.

**Fix.** Add `accounts.disabled_at`. In `disable_account`, in one transaction,
delete every `sessions` row (both token types), every `refresh_tokens` row,
pending `auth_codes`, `consent_requests` and `login_tokens` for the account.
Check `disabled_at` in `get_session_account`, `authenticate`, `handle_token`
(both grants) and `handle_authorize`. Add an enable endpoint.

## H2 — High — one stranger can lock everybody out of signing in

**Proof:** `SecurityAudit.H2_OneClientsFailuresDoNotLockOutEveryone`. Four
failed logins for made-up usernames from `172.18.0.1` lock out `alice`'s
correct login from the same address, and `X-Forwarded-For` is ignored. The
deployment half is reasoned from the files cited below.

**Attacker story.** In the shipped deployment, nginx proxies to
`127.0.0.1:8480` (`deploy/nginx/bsfchat.conf.template:510-517`), which docker
publishes into the container (`deploy/docker-compose.yml`, `127.0.0.1:8480:8480`).
The service therefore sees every request arriving from the same docker gateway
address. `AccountHandler::client_key` (`src/api/AccountHandler.cpp:141-143`)
keys every limiter on `req.remote_addr`. So:

* 8 failed logins from anyone set `login-ip:<gateway>` and lock **every** user
  out of `/api/login` for 15 minutes (`:326-334`). A script that sends 8 bad
  passwords every 15 minutes stops all BSFChat ID sign-ins, and with them every
  `m.login.token` sign-in on every chat server.
* The request limiter allows 10 logins, 10 registrations and 10 2FA attempts
  per 5 minutes **for the whole platform** (`:220`, `:302`, `:702`).
* The same applies to `2fa-ip:` (`:724-729`).

Because `X-Forwarded-For` is ignored, it cannot be spoofed to bypass the limit.
That is the good news. The bad news is that it is not used at all.

**Fix.** Mirror the chat server: add `trusted_proxies` (CIDRs, default empty).
When the TCP peer is trusted, take the right-most untrusted address from
`X-Forwarded-For`. Otherwise ignore the header. Ship the deploy template with
`172.16.0.0/12`, the docker bridge range, as the chat server's deployment already needs. Separately,
make the per-IP lockout a throttle rather than a hard lockout that also blocks
correct passwords, because per-IP hard lockouts are a DoS primitive even with
correct addresses.

## H3 — High — login CSRF into a lookalike account

**Proof:** `SecurityAudit.H3_LoginRejectsNonJsonContentType`. A `text/plain`
body `{"username":…,"password":…,"x":"="}\r\n` with a foreign `Origin` returns
200 and a `Set-Cookie`. Also `SecurityAudit.H3b_ConfusableUsernamesAreRefused`:
`Alice`, `аlice` (Cyrillic а) and `alice` followed by U+200B all register
alongside `alice`. That browsers store a `SameSite=Lax` cookie from the response
to a cross-site top-level form POST is reasoned from the cookie specification,
not demonstrated in a browser.

**Attacker story.** Mallory registers `аlice`, with a Cyrillic а. A page Alice
visits auto-submits
`<form method=POST action=https://id.bsfchat.com/api/login enctype=text/plain>`
with the input named `{"username":"аlice","password":"…","x":"` and valued `"}`.
No preflight is involved, and the top-level response sets the session cookie,
so Alice's browser is now signed in to Mallory's identity. The next time her
client runs "Sign in with BSFChat ID", the consent page says "wants to sign you
in as **аlice**", and she clicks Allow. From then on she chats inside Mallory's
`@oidc_…` account on every server, and Mallory can read her DMs later. If she
runs the account-link step while in this state, Mallory's identity is linked,
permanently, to Alice's real account.

**Cause.** Every JSON handler does `json::parse(req.body)` without checking
`Content-Type` (`AccountHandler.cpp:228, 310, 450, 624, 671, 710`;
`AdminHandler.cpp:120`). No `Origin` check exists. Usernames are only
length-checked (`AccountHandler.cpp:243`), and SQLite's `UNIQUE` is
case-sensitive and byte-exact (`IdentityStore.cpp:106`).

**Fix.** Refuse state-changing requests unless the content type is
`application/json`, which forces a CORS preflight that the wildcard ACAO without
credentials cannot satisfy. Also check `Origin`/`Sec-Fetch-Site` against the
issuer origin on cookie-authenticated POST/PUT/DELETE. Restrict usernames to a
small ASCII grammar (for example `[a-z0-9._-]{3,32}`, compared case-folded), or
apply the UTS #39 skeleton check the server already uses for homoglyphs.
Consider `SameSite=Strict` for the session cookie: nothing needs it on
cross-site navigation, because `/authorize` bounces through `login.html`
anyway.

## H4 — High — stolen credentials cannot be evicted

**Proof:** `SecurityAudit.H2b_PasswordChangeRevokesOtherSessionsAndRefreshTokens`.
After a password change, another browser session still reads the profile, and a
refresh token issued earlier still refreshes. See also M3.

**Attacker story.** Alice notices odd activity and changes her password. The
attacker's session cookie and the refresh token lifted from her machine carry
on. The refresh token rotates on every use, so its 30-day lifetime
(`OidcHandler.cpp:635, 712`) never expires. It is not listed anywhere Alice can
see (`list_sessions_for_account` filters to browser sessions). Logout
(`AccountHandler.cpp:398-415`) deletes only the presenting session. The only way
to kill a refresh token is `/token/revoke` with the token itself.

**Fix.** On password change, 2FA enable or disable, and on an explicit "sign out
everywhere", delete every other session and every refresh token for the
account. List refresh tokens (per client, created and last used) in the sessions
tab with a revoke button. Give refresh tokens an absolute lifetime that
rotation does not extend, and detect reuse of a rotated token (revoke the
family).

---

## M1 — Medium — stored XSS in the account portal through `server_url`

**Proof:** the server half is proven by
`SecurityAudit.M1_ServerUrlCannotCarryScript`:
`https://x.example/');alert(document.domain);//` is accepted with an `openid`
access token. The DOM half is reasoned (the in-browser reproduction page could
not be executed in this environment).

**Attacker story.** A relying party that Alice once signed in to holds her
`openid` access token, which is enough for `/api/servers` (M5). It adds that
URL with the name "Click remove". Alice sees a server she does not recognise in
her profile and clicks **Remove**. `profile.html:392` renders
`onclick="removeServer('${escapeHtml(s.server_url)}')"`, and `escapeHtml`
(`web/js/app.js:54`) is `textContent` → `innerHTML`, which escapes `& < >` but
**not quotes** (HTML fragment serialisation of a text node). The `'` ends the JS
string, and the attacker's code runs on the identity origin with Alice's browser
session. It can change her email and display name, add servers (C1), start 2FA
setup and read the secret, and drive the consent flow. This escalates an
`openid` scope into full portal control.

**Cause.** `server_url_acceptable` (`AccountHandler.cpp:95-119`) rejects
controls and whitespace but not `'`, `"`, `(` or `)`, and the page puts data
inside an inline handler. `profile.html:354` has the same pattern with
`s.full_id`.

**Fix.** Build rows with `createElement`/`textContent`, and attach listeners
with `addEventListener`, capturing the value in a closure. Send a CSP with no
`unsafe-inline` on all static pages (L7). Normalise and re-serialise
`server_url` server-side (for example, reject anything that does not
round-trip through a URL parser to itself, and percent-encode `'`).

## M2 — Medium — second factor: replay, and no per-account guess limit

**Proof:** `SecurityAudit.M2_TotpCodeCannotBeReplayed` shows the same code
completing two logins. `SecurityAudit.M2b_SecondFactorGuessingIsLimitedPerAccount`
shows that after 12 wrong codes from 4 addresses the account still hands out
fresh login tokens.

**Attacker story.** (a) A phishing proxy or a shoulder-surfer who captures one
code signs in again within about 90 s (window ±1, `Totp.cpp:140-164`, and no
last-used step is stored). (b) With Alice's password, Mallory requests a login
token, burns its `totp_max_attempts` guesses, and requests another one from a
different address. The limits are per-token and per-IP only
(`AccountHandler.cpp:724-763`). Nothing counts wrong codes per account. With
IPv6 or a botnet, and after H2 is fixed so that per-IP limits are real, 10⁶/3
guesses is a matter of hours.

**Fix.** Store the last accepted TOTP step per account and require
`step > last_step`. Count second-factor failures per account in
`login_failures_` (key `2fa-user:<id>`), and on lockout refuse to issue new
login tokens for that account. Notify the user.

## M3 — Medium — session revocation does not work

**Proof:** `SecurityAudit.M3_SessionsCanBeRevokedFromTheList`: DELETE with the
id that the list returned gets a 404.

**Cause.** `handle_list_sessions` returns `session_id.substr(0, 8) + "..."`
(`AccountHandler.cpp:517`), `handle_revoke_session` looks up the full id
(`:549`), and the page calls `revokeSession(s.full_id)`, a field that is never
sent (`profile.html:354`), so it posts `undefined`. Users cannot end a session
they do not hold.

**Fix.** Return an opaque per-session handle (for example, a random `id`
column, or HMAC(session_id)), and revoke by handle.

## M4 — Medium — the email address goes to every relying party

**Proof:** `SecurityAudit.M4_IdTokenOmitsEmailWithoutEmailScope`. With scope
`openid profile`, which is what the desktop client requests, the id_token
contains `email`.

**Impact.** `create_id_token` (`OidcHandler.cpp:830-832`) always includes
`email`, `name` and `picture`. `/userinfo` gates by scope correctly
(`:770-778`), but the id_token is what every chat server receives. Every chat
server operator, hostile ones included (C1), learns every user's email address,
which the user was told was optional. The email is also unverified and there is
no `email_verified` claim, so no relying party should ever key anything on it.

**Fix.** Pass the granted scope into `create_id_token`. Emit `email` only
under `email`, and `name`/`picture`/`preferred_username` only under `profile`.
Add `email_verified: false` until verification exists.

## M5 — Medium — any relying party can rewrite the desktop client's server list

**Proof status:** reasoned. The capability is documented and tested as
intended (`TokenSeparationTest.AccessTokenCanStillSyncServerList`,
`AccountHandler.cpp:74-81`). The client auto-connects to every entry
(`client/src/net/ServerManager.cpp:720-745`).

`/api/servers` accepts an `openid`-scoped access token from **any** client, not
only `bsfchat-desktop`. Any OAuth client that an admin registers (and any
future third-party app) can add a hostile server to a user's list, and the
user's client will connect to it and sign in (C1). It can also plant the XSS
payload (M1).

**Fix.** Require `client_id == "bsfchat-desktop"` on the access token for
`/api/servers`, or introduce a `bsfchat:servers` scope that only the desktop
client requests and that is shown on the consent page.

---

## Low

**L1 — no `nonce` (proven: `SecurityAudit.Lnonce_NonceIsEchoedIntoIdToken`).**
`handle_authorize` never reads `nonce`, and the id_token never carries it. With
PKCE this is not exploitable on its own, but it leaves relying parties no
replay binding. Also missing: `auth_time`, `azp`, `jti`. Fix: bind `nonce` to
the consent request and code, and echo it.

**L2 — account enumeration (partly proven: `SecurityAudit.Lenum_TakenEmailIsNotDistinguishableAsServerError`).**
Registering with an email already in use hits `email UNIQUE` →
`INSERT OR IGNORE` fails → **500** (`AccountHandler.cpp:269-271`,
`IdentityStore.cpp:107,312`). Login for an unknown username returns before any
PBKDF2 runs (`AccountHandler.cpp:336-338`), about 600k iterations faster than
for a real one, so response time separates real usernames from fake ones.
`/register` returns 409 for a taken username (inherent). A PUT to
`/api/profile` with another user's email silently fails to save but returns 200
with the new value (`:489-499`, return value of `update_account` ignored). Fix:
verify against a dummy hash for unknown users, return a generic registration
error, and check the `update_account` result.

**L3 — `RAND_bytes` return value unchecked (reasoned).**
`AccountHandler.cpp:29, 44, 123`, `OidcHandler.cpp:30`, `AdminHandler.cpp:24`.
On failure, the `std::vector` sites yield an **all-zero** token (auth codes,
access, refresh and consent tokens, client secrets), and the stack-array sites
yield uninitialised memory. OpenSSL 3 on Linux practically never fails here,
but the consequence of a failure would be forgeable credentials. Fix: one
shared `secure_random_hex(n)` that throws (or aborts) unless
`RAND_bytes(...) == 1`, as `PasswordHash.cpp:120` and `Totp.cpp:91,182`
already do.

**L4 — refresh-token rotation is not atomic (reasoned).** `get_refresh_token`
(`OidcHandler.cpp:656`) and `delete_refresh_token` (`:706`) run in separate
transactions, so two concurrent refreshes of one token both succeed and fork
it. There is no reuse detection, and a replayed authorization code does not
revoke the tokens the first redemption issued (RFC 6749 §4.1.2 SHOULD). Fix:
`consume_refresh_token` in one transaction, like `consume_auth_code`.

**L5 — credentials at rest (reasoned).** Browser sessions, access tokens and
refresh tokens are stored as the raw bearer value (`sessions.session_id`,
`refresh_tokens.token`), and so are client secrets. A copy of `identity.db` (a
backup, for instance: `deploy/backup.sh` archives it) is a set of live
credentials. `private.pem` is written with `std::ofstream` and the process
umask (`KeyManager.cpp:44-54`), normally 0644. The deploy mitigates this with a
0750 data directory. Fix: store SHA-256 of tokens and look up by hash, and
create the key file 0600.

**L6 — targeted lockout (reasoned).** Anyone who knows a username can lock it
out for 15 minutes with 8 bad passwords (`login-user:` key, `AccountHandler.cpp:327`).
This is a known trade-off. Once H2 is fixed, consider throttling (growing
delay) rather than a hard lockout, and never block a login that also passes
2FA.

**L7 — no security headers on static pages (reasoned).** Only the consent page
sets `X-Frame-Options`/`frame-ancestors` (`OidcHandler.cpp:350-355`).
`login.html`, `profile.html` and `admin.html` can be framed (clickjacking the
profile's Remove and Add server buttons), and no CSP exists, which is what
would have neutralised M1. Fix: a post-routing handler that adds
`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer` to every
response.

**L8 — log hygiene (reasoned).** `Failed login for '{}' from {}`
(`AccountHandler.cpp:341`) logs the raw submitted username, which lets an
attacker inject newlines into logs and puts mistyped passwords into them.
`Account created: {}` (`:274`) does the same. No tokens, secrets or passwords
are logged otherwise.

**L9 — HTTP server defaults when exposed directly (reasoned).** httplib's
default body limit is 100 MB, buffered in memory per request, with up to 4×
pool threads in flight. Its thread-per-connection model can be held by slow
senders (5 s per read, keep-alive up to 100 requests). The shipped nginx
(default `client_max_body_size 1m`, request buffering on) absorbs both.
Anyone running the service without a proxy does not get that. Fix:
`set_payload_max_length(64 KiB)` and explicit read timeouts in `HttpServer`.
`/token/revoke` is unauthenticated (RFC 7009 expects client authentication for
confidential clients). This is harmless, because knowing the token is already
full power.

**L10 — unbounded, unvalidated profile fields (reasoned).** `display_name`,
`avatar_url` and `email` have no length, type or character checks
(`AccountHandler.cpp:462-464`). A non-string value throws and returns a 500.
These values go into every id_token (`name`, `picture`, `email`) and from there
into chat-server display names (`server/src/api/AuthHandler.cpp:576-577`).
Newlines, bidi controls and megabyte names are all accepted. Fix: type checks,
length caps, reject controls and bidi overrides, and require `https:` for
`avatar_url`.

## Informational

* JWKS publishes a single key with a fixed `kid` (`bsfchat-id-1`) and there is
  no rotation procedure. Replacing `private.pem` invalidates everything at
  once. RSA-2048 via OpenSSL EVP. Consider a `kid` derived from the key and
  publishing old and new keys during a rotation.
* Discovery advertises `registration_endpoint: /register`, which is *user*
  registration, not RFC 7591 client registration. A generic OIDC library that
  tries dynamic client registration will be confused.
* `scope` is not validated, `openid` is not required for an id_token, and
  unknown scopes are stored and echoed.
* Backup codes use `byte % 62`. The bias is negligible (about 47.6 bits per
  code).
* `/2fa/disable` needs the password but not a current second factor.
* Admin: accounts can only be made admin by editing the database. There is no
  re-enable, no audit trail, the user list is capped at 100 with no paging, and
  the disabled state is not visible.
* `web/js/qrcode.min.js` is an empty file, so the 2FA QR code never renders
  and the page falls back to printing the otpauth URI. This is a functional
  bug, not a security one.
* Discovery exposes the exact build (`bsfchat_version`/`bsfchat_revision`).
  This is deliberate and documented.

---

## Verified correct

These were checked and found sound. A clean area is a result.

**Randomness: every secret comes from a CSPRNG.** No `std::mt19937`,
`std::random_device`, `rand()` or `std::uniform_*` appears anywhere in `src/`.
Inventory:

| Secret | Where | RNG | Size |
| --- | --- | --- | --- |
| Consent token | `OidcHandler.cpp:291` → `random_hex` | OpenSSL `RAND_bytes` | 256 bit |
| Authorization code | `OidcHandler.cpp:398` | `RAND_bytes` | 256 bit |
| Access token | `OidcHandler.cpp:837` | `RAND_bytes` | 256 bit |
| Refresh token | `OidcHandler.cpp:613, 691` | `RAND_bytes` | 256 bit |
| Browser session id | `AccountHandler.cpp:42` | `RAND_bytes` | 256 bit |
| 2FA login token | `AccountHandler.cpp:363` → `generate_hex_token` | `RAND_bytes` | 256 bit |
| Account id / `sub` | `AccountHandler.cpp:27` (UUIDv4) | `RAND_bytes` | 122 bit (not a secret) |
| OAuth client_id / secret | `AdminHandler.cpp:135-136` | `RAND_bytes` | 128 / 256 bit |
| Password salt | `PasswordHash.cpp:120` | `RAND_bytes` (checked) | 128 bit |
| TOTP secret | `Totp.cpp:89-95` | `RAND_bytes` (checked) | 160 bit |
| Backup codes | `Totp.cpp:173-192` | `RAND_bytes` (checked) | about 47.6 bit each |
| RSA signing key | `protocol/src/JwtUtils.cpp:305` | OpenSSL `EVP_PKEY_keygen` | 2048 bit |

The only weakness is L3 (unchecked return values), not the generator.

**Passwords.** PBKDF2-HMAC-SHA256 at 600,000 iterations, with the config clamped
to ≥100,000 and a 16-byte salt per hash. The iteration count is recorded in the
hash, and parsing caps it at 50 M, so a hostile row cannot pin the CPU. Legacy
hashes are upgraded on login. The comparison uses `CRYPTO_memcmp`.

**Constant-time comparisons** for the client secret, the PKCE challenge, the
password hash, backup codes and TOTP (all candidate steps, no early exit).

**redirect_uri.** An exact match is required, except for loopback `http`
registrations, where only the port is free (RFC 8252 §7.3). Path and query must
match exactly. Userinfo (`localhost:1@evil`) and fragments are rejected. The
`bsfchat-desktop` registration was narrowed to `/oauth/callback`. An invalid
redirect_uri is reported in-band and never redirected to. Backslash, percent
and port-injection variants all fail the parser or the path comparison.

**Authorization code.** 256-bit, 5-minute lifetime, single use via an atomic
fetch-and-delete (`IdentityStore.cpp:537-573`), bound to `client_id` and
`redirect_uri`, and `redirect_uri` is required at `/token`.

**PKCE.** Mandatory for public clients at both `/authorize` and `/token`. Only
S256 is accepted, and `plain` is rejected. Challenge and verifier lengths are
checked. A challenge cannot be stripped from a public client, and a confidential
client that sent a challenge must present the verifier.

**Consent.** A GET never mints a code. The consent token is 256-bit, bound to
the issuing browser session in SQL, single use, and valid for 5 minutes. It is
not consumed by a mismatched session. The page is `no-store`, cannot be framed,
and every interpolated value passes through `html_escape`, which covers
`& < > " '`.

**state and login redirect.** `state` is percent-encoded into every redirect.
`login.html` only ever navigates to `/authorize?…` or `/profile.html`, so it is
not an open redirect.

**Token endpoint client authentication.** A confidential client must present
its secret and it must match. HTTP Basic takes precedence, and a conflicting
body `client_id` is rejected. A public client presenting a secret is rejected.
`Cache-Control: no-store` is set on token responses.

**Credential separation.** Access tokens cannot act as portal sessions and the
reverse. `/userinfo` requires `openid` and gates claims by scope. `/token/revoke`
cannot delete browser sessions.

**Signing and algorithm confusion.** id_tokens are RS256, with `iss`, `aud`,
`iat` and `exp` set. The chat-server verifier (`protocol/src/JwtUtils.cpp:62`)
pins `allow_algorithm(rs256(pem))`, so `alg:none` and HS256-with-the-public-key
tokens are rejected by jwt-cpp's algorithm check. It also enforces the issuer
and requires `aud` to be present when an audience is configured.

**Session cookie.** 256-bit, `HttpOnly; SameSite=Lax; Secure` (configurable,
default on), with a fresh id minted on every login, so there is no fixation.
Logout deletes the session and expires the cookie. The cookie parser is
anchored to the whole name.

**2FA mechanics.** The window is ±1 step. The login token burns after N wrong
codes. Backup codes are PBKDF2-hashed at rest and consumed atomically. Setup
cannot silently downgrade an enrolled factor. Codes that are not 6 digits skip
the HMAC work.

**SQL.** Every statement is a prepared statement with bound parameters. The
only concatenations are compile-time constants (`kSessionColumns`) and an
integer (`PRAGMA user_version`).

**HTTP parsing (cpp-httplib 0.47.0).** Rejects conflicting duplicate
`Content-Length` (RFC 9110 §8.6), a non-zero `Content-Length` combined with
`Transfer-Encoding` (RFC 9112 §6.3), non-numeric `Content-Length`, URIs over
8 KiB, and more than 100 headers or header lines over 8 KiB. An oversized
`Content-Length` saturates at `ULLONG_MAX` in `strtoull` and is then refused by
the 100 MB payload limit, so it does not wrap. Static files go through
httplib's `is_valid_path` (no `..` escape). Handler exceptions produce a bare
500 without the message. The shipped nginx in front normalises framing, which
removes the smuggling surface between the two.

**CORS.** `Access-Control-Allow-Origin: *` with no `Allow-Credentials`, so
browsers never send cookies on a cross-origin request whose response a page can
read.

**Admin API.** Requires a browser session and `is_admin`. Access tokens cannot
reach it. The client listing omits secrets.

**Secrets in logs.** No token, password, code or secret is logged (apart from
the username misuse in L8).

---

## Not reached

* **No live server was run** and nothing was fuzzed at the socket level. HTTP
  parsing conclusions come from reading httplib 0.47.0's source, and nginx's
  behaviour from the shipped config.
* **Browser behaviour was not demonstrated**: the cookie being stored in H3,
  and the quote break-out in M1. Both are reasoned from the specifications. A
  local reproduction page was written, but this environment would not execute
  it.
* **Chat-server side** beyond the id_token verify call, `m.login.token` and
  `link_identity`: JWKS fetching and caching, issuer discovery and key rollover
  in `server/src/auth/OidcAuth.cpp`.
* **Desktop client's loopback callback listener**
  (`client/src/identity/IdentityClient.cpp`): state checking and handling of
  concurrent callbacks.
* **Concurrency**: the refresh-token race (L4) was not exercised.
* **jwt-cpp, nlohmann/json (deep-nesting limits), OpenSSL configuration.**
* **Production state**: whether `link_identity` is deployed (C1's severity
  there depends on it), which OAuth clients exist besides `bsfchat-desktop` (M5),
  and the real key-file permissions. The production host was not contacted,
  per instructions.

## Builds and tests made for this audit

* One configure and one build (`nice -n 19`, `-j2`) of the
  `identity_security_audit_tests` target only. Dependencies came from the
  already-fetched `identity/build-main/_deps`, and protocol from the clean
  sibling checkout at `origin/main` (`3fd3f23`). Nothing was downloaded.
* One run of `identity_security_audit_tests`: 13 tests, 13 failures, each
  proving its finding as described above. The regular `identity_tests` suite
  was neither rebuilt nor run.
