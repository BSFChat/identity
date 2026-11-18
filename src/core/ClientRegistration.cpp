#include "core/ClientRegistration.h"
#include "core/Logger.h"

#include <chrono>
#include <string>
#include <vector>

namespace bsfchat::id {

namespace {

// Two first-party PUBLIC clients (empty secret, so PKCE is mandatory at both
// /authorize and /token — authenticate_client() and the PublicClient* cases in
// tests/test_auth_flows.cpp pin that):
//
//   * "bsfchat-desktop" — RFC 8252 §7.3 loopback. The client binds an
//     ephemeral port and listens on /oauth/callback; registering the full path
//     lets redirect_uri_matches() relax only the port.
//
//   * "bsfchat-mobile" — RFC 8252 §7.2 claimed https redirect, one exact URL
//     ([apps] mobile_redirect_uri). Android delivers it only to the app whose
//     signing key the domain's assetlinks.json names, and iOS only to the app
//     its apple-app-site-association names.
//
// Why mobile stopped sharing bsfchat-desktop's "bsfchat://oauth/callback": a
// private-use scheme cannot be reserved. PKCE stops another app from spending
// the REAL app's code, but nothing stopped another app from starting its OWN
// sign-in as bsfchat-desktop with that redirect: the consent page truthfully
// said "BSFChat Desktop", and one tap of Allow gave the impostor a token for
// the user's chat server plus write access to their server list (M5). With a
// claimed https redirect the OS will not hand the code to that app at all.
//
// The desktop loopback has the same property in principle (any local process
// can bind a port, RFC 8252 §8.6), but a process already running on your
// desktop is a different threat from an app installed from a store.
constexpr const char* kDesktopClientId = "bsfchat-desktop";
constexpr const char* kMobileClientId = "bsfchat-mobile";

constexpr const char* kDesktopRedirectUris =
    R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback"])";
// Only with [apps] allow_legacy_mobile_scheme: mobile builds from before
// bsfchat-mobile existed still sign in as bsfchat-desktop through this.
constexpr const char* kDesktopWithLegacySchemeRedirectUris =
    R"(["http://127.0.0.1/oauth/callback","http://localhost/oauth/callback","bsfchat://oauth/callback"])";

// Values shipped previously. Only an exact match is rewritten, so an operator
// who has customised the list keeps what they wrote.
//
// The bare-localhost one matched any path on any localhost port.
constexpr const char* kLegacyDesktopRedirectUris = R"(["http://localhost"])";

// The private-use scheme the I2-3 warnings look for.
constexpr const char* kLegacyScheme = "bsfchat://";

std::string json_string_array_of_one(const std::string& uri) {
    // The value has passed Config's https/no-fragment check; quote and
    // backslash are escaped anyway so the stored JSON is always well formed.
    std::string out = "[\"";
    for (char c : uri) {
        if (c == '"' || c == '\\') out += '\\';
        out += c;
    }
    out += "\"]";
    return out;
}

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

const char* first_party_redirect_uris() { return kDesktopRedirectUris; }
const char* desktop_client_id() { return kDesktopClientId; }
const char* mobile_client_id() { return kMobileClientId; }

bool is_first_party_client(const std::string& client_id) {
    return client_id == kDesktopClientId || client_id == kMobileClientId;
}

std::vector<std::string> ensure_first_party_client(IdentityStore& store, const Config& config) {
    auto log = get_logger();
    std::vector<std::string> warnings;

    // --- bsfchat-desktop ----------------------------------------------------
    const char* desktop_uris = config.allow_legacy_mobile_scheme
                                   ? kDesktopWithLegacySchemeRedirectUris
                                   : kDesktopRedirectUris;
    auto desktop = store.get_oauth_client(kDesktopClientId);
    if (!desktop.has_value()) {
        OAuthClient client;
        client.client_id = kDesktopClientId;
        client.client_secret = ""; // public client — authenticates via PKCE
        client.name = "BSFChat Desktop";
        client.redirect_uris = desktop_uris;
        client.created_at = now_seconds();
        store.create_oauth_client(client);
    } else if (desktop->redirect_uris != desktop_uris &&
               (desktop->redirect_uris == kLegacyDesktopRedirectUris ||
                desktop->redirect_uris == kDesktopRedirectUris ||
                desktop->redirect_uris == kDesktopWithLegacySchemeRedirectUris)) {
        // One of the shapes this code has shipped, so it is ours to move:
        // narrowing the bare-localhost entry, dropping bsfchat:// (the
        // default now), or re-adding it when the operator asked for the
        // transition. A list an operator wrote by hand is left alone.
        store.update_oauth_client_redirect_uris(kDesktopClientId, desktop_uris);
        log->info("Set bsfchat-desktop redirect_uris to {}", desktop_uris);
        if (!config.allow_legacy_mobile_scheme &&
            desktop->redirect_uris.find(kLegacyScheme) != std::string::npos) {
            warnings.push_back(
                "bsfchat://oauth/callback was removed from bsfchat-desktop's redirects "
                "([apps] allow_legacy_mobile_scheme = false). Mobile app builds from before "
                "the bsfchat-mobile client (old TestFlight or store builds) can no longer sign "
                "in. Set allow_legacy_mobile_scheme = true for a transition period if anyone "
                "still uses one.");
        }
    }

    // --- bsfchat-mobile -----------------------------------------------------
    // Fully managed from [apps] mobile_redirect_uri: the redirect is where the
    // OS routes codes to the verified app, and it has to agree with the
    // domain the app was built for, so config is the one source of truth.
    const std::string mobile_uris = json_string_array_of_one(config.mobile_redirect_uri);
    auto mobile = store.get_oauth_client(kMobileClientId);
    if (!mobile.has_value()) {
        OAuthClient client;
        client.client_id = kMobileClientId;
        client.client_secret = ""; // public client — authenticates via PKCE
        client.name = "BSFChat";
        client.redirect_uris = mobile_uris;
        client.created_at = now_seconds();
        store.create_oauth_client(client);
        log->info("Registered the bsfchat-mobile client ({})", config.mobile_redirect_uri);
    } else if (mobile->redirect_uris != mobile_uris) {
        store.update_oauth_client_redirect_uris(kMobileClientId, mobile_uris);
        log->info("Set bsfchat-mobile redirect_uris to {}", mobile_uris);
    }

    // A registration an operator wrote by hand is never rewritten above, so
    // it can keep the scheme the switch says is off. Say so.
    if (!config.allow_legacy_mobile_scheme) {
        for (const auto& client : store.list_oauth_clients()) {
            if (client.redirect_uris.find(kLegacyScheme) == std::string::npos) continue;
            warnings.push_back(
                "OAuth client '" + client.client_id + "' still lists a bsfchat:// redirect "
                "although [apps] allow_legacy_mobile_scheme = false. Any app on a phone can "
                "claim that scheme; remove it from the registration unless you mean to keep it.");
        }
    }

    for (const auto& w : warnings) log->warn("{}", w);
    return warnings;
}

} // namespace bsfchat::id
