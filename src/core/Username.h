#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace bsfchat::id {

// Username policy for NEW registrations (security audit H3).
//
// Usernames used to be length-checked only, and SQLite's UNIQUE is
// byte-exact, so `Alice`, `аlice` (Cyrillic а) and `alice` + U+200B all
// registered beside `alice`. The consent page says "sign you in as alice",
// so a lookalike account plus a login CSRF put a victim inside an attacker's
// identity without anything on screen looking wrong.
//
// The policy is the chat server's, so a BSFChat username means the same thing
// on both sides: [a-z0-9._-], 1-64 characters, and refused when its confusable
// skeleton (below) equals an existing account's. ASCII-only is what makes a
// small skeleton sufficient — every Unicode lookalike is refused by the
// grammar before the skeleton is consulted.
//
// Like the chat server, this gates registration only. Login stays an exact
// match, and accounts that predate the rule keep working even when their
// names collide under it; refusing an existing user's login would be a far
// worse failure than the one this prevents.
std::optional<std::string> username_policy_error(std::string_view username);

// Lossy confusable folding: separators dropped, ASCII lowercased, 0->o, 1->l,
// then m->rn and w->vv expanded so every spelling of the same shape lands on
// one string. A port of the chat server's localpart_skeleton()
// (server/src/identity/Localpart.cpp); see that file for why each rule is, or
// deliberately is not, there. Non-ASCII bytes pass through unchanged, which
// only matters for pre-policy rows being backfilled.
std::string username_skeleton(std::string_view username);

} // namespace bsfchat::id
