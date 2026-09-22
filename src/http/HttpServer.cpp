#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

namespace bsfchat::id {

HttpServer::HttpServer(const Config& config)
    : bind_address_(config.bind_address)
    , port_(config.port) {
    // httplib buffers a whole body in memory, up to 100 MB by default, on
    // each of its pool threads. Nothing this service accepts is more than a
    // few KiB. The shipped nginx caps bodies at 1 MB already; this protects a
    // deployment without it (security audit L9).
    server_.set_payload_max_length(64 * 1024);
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    auto log = get_logger();
    log->info("Starting HTTP server on {}:{}", bind_address_, port_);
    server_.listen(bind_address_, port_);
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat::id
