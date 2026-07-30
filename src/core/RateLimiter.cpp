#include "core/RateLimiter.h"

namespace bsfchat::id {

namespace {

int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

} // namespace

RateLimiter::RateLimiter(int max_events, std::chrono::seconds window)
    : max_events_(max_events), window_(window) {}

bool RateLimiter::allow(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto now = now_seconds();
    auto cutoff = now - window_.count();

    auto& q = events_[key];
    while (!q.empty() && q.front() <= cutoff) q.pop_front();

    if (static_cast<int>(q.size()) >= max_events_) {
        return false;
    }
    q.push_back(now);
    return true;
}

void RateLimiter::reset(const std::string& key) {
    std::lock_guard lock(mutex_);
    events_.erase(key);
}

void RateLimiter::prune() {
    std::lock_guard lock(mutex_);
    auto cutoff = now_seconds() - window_.count();
    for (auto it = events_.begin(); it != events_.end();) {
        auto& q = it->second;
        while (!q.empty() && q.front() <= cutoff) q.pop_front();
        it = q.empty() ? events_.erase(it) : std::next(it);
    }
}

FailureTracker::FailureTracker(int max_failures, std::chrono::seconds lockout)
    : max_failures_(max_failures), lockout_(lockout) {}

bool FailureTracker::is_locked(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    if (it->second.locked_until > now_seconds()) return true;
    // Lockout elapsed — start the counter over rather than letting the attacker
    // resume from max_failures - 1.
    if (it->second.locked_until != 0) {
        entries_.erase(it);
    }
    return false;
}

bool FailureTracker::record_failure(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto now = now_seconds();
    auto& e = entries_[key];

    // Forget stale failure history so an honest user who mistypes once a week
    // is not gradually locked out.
    if (e.last_failure != 0 && now - e.last_failure > lockout_.count()) {
        e.failures = 0;
        e.locked_until = 0;
    }

    e.failures += 1;
    e.last_failure = now;
    if (e.failures >= max_failures_) {
        e.locked_until = now + lockout_.count();
        return true;
    }
    return false;
}

void FailureTracker::clear(const std::string& key) {
    std::lock_guard lock(mutex_);
    entries_.erase(key);
}

int64_t FailureTracker::retry_after(const std::string& key) {
    std::lock_guard lock(mutex_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return 0;
    auto remaining = it->second.locked_until - now_seconds();
    return remaining > 0 ? remaining : 0;
}

void FailureTracker::prune() {
    std::lock_guard lock(mutex_);
    auto now = now_seconds();
    for (auto it = entries_.begin(); it != entries_.end();) {
        bool expired = it->second.locked_until <= now &&
                       (now - it->second.last_failure) > lockout_.count();
        it = expired ? entries_.erase(it) : std::next(it);
    }
}

} // namespace bsfchat::id
