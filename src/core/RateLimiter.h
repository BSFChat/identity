#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bsfchat::id {

// Fixed sliding-window rate limiter, keyed by an arbitrary string (typically
// remote address, or remote address + username). In-memory and per-process:
// the identity service is a single process, so this is sufficient. It is NOT a
// substitute for an edge rate limit if the service is ever run replicated.
class RateLimiter {
public:
    RateLimiter(int max_events, std::chrono::seconds window);

    // Records an attempt and returns true if it is within the limit.
    bool allow(const std::string& key);

    // Drops the recorded history for a key (e.g. after a successful login).
    void reset(const std::string& key);

    // Removes entries whose window has fully elapsed. Called by the background
    // sweeper so the map cannot grow without bound under attack.
    void prune();

private:
    int max_events_;
    std::chrono::seconds window_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<int64_t>> events_;
};

// Counts consecutive failures for a key and locks it out for a period once a
// threshold is crossed. Used to make credential and TOTP guessing expensive.
class FailureTracker {
public:
    FailureTracker(int max_failures, std::chrono::seconds lockout);

    // True while the key is locked out.
    bool is_locked(const std::string& key);

    // Records a failure; returns true if the key is now locked out.
    bool record_failure(const std::string& key);

    // Clears the failure history for a key (call on success).
    void clear(const std::string& key);

    // Seconds remaining on an active lockout, or 0.
    int64_t retry_after(const std::string& key);

    void prune();

private:
    struct Entry {
        int failures = 0;
        int64_t locked_until = 0;
        int64_t last_failure = 0;
    };

    int max_failures_;
    std::chrono::seconds lockout_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
};

} // namespace bsfchat::id
