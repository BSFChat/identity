#include "core/Username.h"

#include <algorithm>

namespace bsfchat::id {

namespace {

constexpr size_t kMaxUsernameLength = 64;

bool is_separator(char c) {
    return c == '.' || c == '_' || c == '-';
}

} // namespace

std::optional<std::string> username_policy_error(std::string_view username) {
    if (username.empty() || username.size() > kMaxUsernameLength) {
        return "Username must be 1-64 characters";
    }
    // Uppercase is refused rather than folded, as on the chat server: silently
    // storing `alice` when the user typed `Alice` would leave them unable to
    // sign in with what they typed, since login is an exact match.
    if (!std::all_of(username.begin(), username.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || is_separator(c);
        })) {
        return "Username may only contain lowercase letters, digits, '.', '_' and '-'";
    }
    // Nothing but separators folds to an empty skeleton, and "" is also the
    // column default for rows that were never backfilled.
    if (username_skeleton(username).empty()) {
        return "Username must contain at least one letter or digit";
    }
    return std::nullopt;
}

std::string username_skeleton(std::string_view username) {
    std::string folded;
    folded.reserve(username.size());
    // Separators go first so `r.n` cannot dodge the `rn` rule below.
    for (char c : username) {
        if (is_separator(c)) continue;
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        switch (c) {
            case '0': folded.push_back('o'); break;
            case '1': folded.push_back('l'); break;
            default: folded.push_back(c); break;
        }
    }
    // Expand rather than contract: expansion is confluent in a single pass.
    std::string skeleton;
    skeleton.reserve(folded.size() * 2);
    for (char c : folded) {
        if (c == 'm') {
            skeleton += "rn";
        } else if (c == 'w') {
            skeleton += "vv";
        } else {
            skeleton.push_back(c);
        }
    }
    return skeleton;
}

} // namespace bsfchat::id
