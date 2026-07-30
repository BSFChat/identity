#pragma once

#include "core/Config.h"
#include "http/HttpServer.h"
#include "store/IdentityStore.h"
#include "crypto/KeyManager.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace bsfchat::id {

class AccountHandler;

class IdentityServer {
public:
    explicit IdentityServer(Config config);
    ~IdentityServer();

    void start();
    void stop();

    Config& config() { return config_; }
    IdentityStore& store() { return *store_; }
    KeyManager& key_manager() { return *key_manager_; }

private:
    void register_routes();
    // Periodically deletes expired sessions, codes and tokens. Without this the
    // sessions table grew forever: delete_expired_sessions() existed but was
    // never called from anywhere.
    void start_sweeper();
    void stop_sweeper();

    Config config_;
    std::unique_ptr<IdentityStore> store_;
    std::unique_ptr<KeyManager> key_manager_;
    std::unique_ptr<HttpServer> http_server_;
    std::shared_ptr<AccountHandler> account_handler_;

    std::thread sweeper_;
    std::mutex sweeper_mutex_;
    std::condition_variable sweeper_cv_;
    std::atomic<bool> stopping_{false};
};

} // namespace bsfchat::id
