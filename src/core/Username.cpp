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
    const auto skeleton = username_skeleton(username);
    if (skeleton.empty()) {
        return "Username must contain at least one letter or digit";
    }
    // Audit 3: "-alice", "alice." read as typos or as someone else.
    if (is_separator(username.front()) || is_separator(username.back())) {
        return "Username must start and end with a letter or digit";
    }
    if (is_reserved_username(username)) {
        return "That username is reserved. Choose another one.";
    }
    return std::nullopt;
}

bool is_reserved_username(std::string_view username) {
    // Names people would read as the service or its staff (audit 3).
    // Compared by skeleton, so "adm1n", "Ad.min" and "rn0derator" are
    // reserved too.
    static constexpr std::string_view kReserved[] = {
        "admin", "administrator", "root", "support", "bsfchat", "system", "moderator", "mod",
        "help", "helpdesk", "security", "staff", "official", "operator", "sysop", "owner",
        "abuse", "postmaster", "webmaster", "hostmaster", "noreply", "info", "everyone",
        "here", "null", "undefined", "anonymous", "nobody",
    };
    // Reserved names also fold i/l together ("adm1n" -> "admin"). Done here
    // rather than in username_skeleton() so the skeletons stored for
    // existing accounts keep matching.
    auto fold = [](std::string sk) {
        for (auto& c : sk) if (c == 'i') c = 'l';
        return sk;
    };
    const auto skeleton = fold(username_skeleton(username));
    for (auto reserved : kReserved) {
        if (skeleton == fold(username_skeleton(reserved))) return true;
    }
    // "bsfchat-team", "bsfchatsupport": anything that starts with the name.
    return skeleton.rfind(fold(username_skeleton("bsfchat")), 0) == 0;
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
