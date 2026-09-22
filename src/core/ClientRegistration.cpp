#include "core/ClientRegistration.h"
#include "core/Logger.h"

#include <chrono>

namespace bsfchat::id {

namespace {

// "bsfchat-desktop" is the first-party client for every platform, not just
// desktop, and its two registered redirect shapes are the two halves of
// RFC 8252:
//
//   * Loopback (§7.3) — desktop. The client binds an ephemeral port and
//     listens on /oauth/callback. Registering the full path (rather than a
//     bare "http://localhost") lets redirect_uri_matches() relax only the
//     port.
//
//   * Private-use URI scheme (§7.1) — iOS AND Android. Neither has a
//     working loopback option
//     there: handing off to the system browser suspends the app, so nothing
//     ever accepts the callback connection and sign-in hangs. The client
//     presents ASWebAuthenticationSession in-process and takes the redirect
//     from it. redirect_uri_matches() short-circuits its port-flexible rule
//     on any non-http scheme, so this one is matched byte for byte.
//
// Why a private-use scheme is safe to register HERE: nobody can reserve
// "bsfchat://", so a hostile app on the same device can register it too and
// win the redirect. What it cannot do is spend the code — bsfchat-desktop is
// a public client (empty secret), which makes PKCE mandatory at both
// /authorize and /token, and the S256 verifier never leaves the real client.
// That enforcement is load-bearing for this entry specifically: see
// authenticate_client() and the PKCE checks in OidcHandler, and the
// PublicClient* cases in tests/test_auth_flows.cpp that pin them.
//
// The iOS client reuses this client_id rather than getting its own because
// /api/servers is gated on client_id == "bsfchat-desktop" (AccountHandler,
// audit finding M5), and because the admin API only mints CONFIDENTIAL
// clients — the wrong shape for an app that cannot keep a secret.
constexpr const char* kDesktopRedirectUris =
    R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback","bsfchat://oauth/callback"])";

// Values shipped previously. Each is upgraded in place on startup, and only
// an exact match is touched, so an operator who has customised the list keeps
// what they wrote.
//
// The bare-localhost one matched any path on any localhost port.
constexpr const char* kLegacyDesktopRedirectUris = R"(["http://localhost"])";
// Loopback only, from before the iOS client existed. An installation left on
// this value refuses every iOS sign-in with "Invalid redirect_uri for this
// client", so it has to be widened here rather than by hand.
constexpr const char* kLoopbackOnlyDesktopRedirectUris =
    R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback"])";

} // namespace

const char* first_party_redirect_uris() { return kDesktopRedirectUris; }

void ensure_first_party_client(IdentityStore& store) {
    auto log = get_logger();

    // Auto-create the well-known desktop client if it doesn't exist
    auto desktop = store.get_oauth_client("bsfchat-desktop");
    if (!desktop.has_value()) {
        OAuthClient client;
        client.client_id = "bsfchat-desktop";
        client.client_secret = ""; // public client — authenticates via PKCE
        client.name = "BSFChat Desktop";
        client.redirect_uris = kDesktopRedirectUris;
        client.created_at = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        store.create_oauth_client(client);
        return;
    }

    if (desktop->redirect_uris == kLegacyDesktopRedirectUris) {
        // Narrow the existing registration to the paths the client actually
        // uses. Left alone if an operator has customised it.
        store.update_oauth_client_redirect_uris("bsfchat-desktop", kDesktopRedirectUris);
        log->info("Tightened bsfchat-desktop redirect_uris to the callback paths");
    } else if (desktop->redirect_uris == kLoopbackOnlyDesktopRedirectUris) {
        // Widen, not narrow: the loopback entries are unchanged, and the
        // private-use scheme the iOS client redirects to is added alongside.
        store.update_oauth_client_redirect_uris("bsfchat-desktop", kDesktopRedirectUris);
        log->info("Added the bsfchat:// native callback to bsfchat-desktop redirect_uris");
    }
}

} // namespace bsfchat::id
