#include "http/HttpServer.h"
#include "core/Config.h"
#include "core/Logger.h"

#include <stdexcept>
#include <string>

namespace bsfchat::id {

HttpServer::HttpServer(const Config& config)
    : bind_address_(config.bind_address)
    , port_(config.port) {
    // httplib buffers a whole body in memory, up to 100 MB by default, on
    // each of its pool threads. Nothing this service accepts is more than a
    // few KiB. The shipped nginx caps bodies at 1 MB already; this protects a
    // deployment without it (security audit L9).
    server_.set_payload_max_length(64 * 1024);

    // cpp-httplib's default socket option is SO_REUSEPORT, under which a
    // second instance (or anything else) binds the same port without an
    // error and the kernel splits connections between them: a stale or
    // duplicate service silently answers half the traffic (audit 3, M1).
    // SO_REUSEADDR alone still allows a quick restart over TIME_WAIT
    // sockets, and makes a port that is really in use a bind failure.
    server_.set_socket_options([](socket_t sock) {
        httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    });
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    auto log = get_logger();
    log->info("Starting HTTP server on {}:{}", bind_address_, port_);
    // Bind separately so a taken port is an error with a reason rather than
    // listen() quietly returning and the process exiting 0.
    if (!server_.bind_to_port(bind_address_, port_)) {
        throw std::runtime_error("cannot listen on " + bind_address_ + ":" + std::to_string(port_) +
                                 " (is another instance, or another service, already using it?)");
    }
    server_.listen_after_bind();
}

void HttpServer::stop() {
    if (server_.is_running()) {
        server_.stop();
    }
}

} // namespace bsfchat::id
