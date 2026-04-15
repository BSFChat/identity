#include "core/Config.h"
#include "core/Logger.h"
#include "core/IdentityServer.h"

#include <csignal>
#include <iostream>
#include <memory>

static std::unique_ptr<bsfchat::id::IdentityServer> g_server;

void signal_handler(int) {
    if (g_server) g_server->stop();
}

int main(int argc, char* argv[]) {
    bsfchat::id::init_logger("info");
    auto log = bsfchat::id::get_logger();

    bsfchat::id::Config config;
    if (argc > 2 && std::string(argv[1]) == "--config") {
        try {
            config = bsfchat::id::Config::load(argv[2]);
            log->info("Loaded config from {}", argv[2]);
        } catch (const std::exception& e) {
            log->error("Failed to load config: {}", e.what());
            return 1;
        }
    } else {
        config = bsfchat::id::Config::defaults();
        log->info("Using default configuration");
    }

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    try {
        g_server = std::make_unique<bsfchat::id::IdentityServer>(std::move(config));
        g_server->start();
    } catch (const std::exception& e) {
        log->error("Server error: {}", e.what());
        return 1;
    }

    return 0;
}
