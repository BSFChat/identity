#pragma once

#include <spdlog/spdlog.h>
#include <memory>

namespace bsfchat::id {

void init_logger(const std::string& level = "info");
std::shared_ptr<spdlog::logger> get_logger();

} // namespace bsfchat::id
