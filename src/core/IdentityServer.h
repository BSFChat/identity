#pragma once

#include "core/Config.h"
#include "http/HttpServer.h"
#include "store/IdentityStore.h"
#include "crypto/KeyManager.h"

#include <memory>

namespace bsfchat::id {

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

    Config config_;
    std::unique_ptr<IdentityStore> store_;
    std::unique_ptr<KeyManager> key_manager_;
    std::unique_ptr<HttpServer> http_server_;
};

} // namespace bsfchat::id
