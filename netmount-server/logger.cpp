// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#include "logger.hpp"
#if defined(SHIFT_JIS) && defined(_WIN32)
#include "unicode_to_ascii.hpp"
#endif

#include <array>
#include <chrono>
#include <cstdio>

constexpr auto LOG_LEVEL_C_STR =
    std::to_array<const char *>({"CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG", "TRACE"});

LogLevel global_log_level = LogLevel::WARNING;

namespace detail {

void log(LogLevel level, const std::string & message) {
    auto now = std::chrono::system_clock::now();
    auto formatted_message = std::format(
        "{:%FT%TZ} {} {}",
        std::chrono::time_point_cast<std::chrono::milliseconds>(now),
        LOG_LEVEL_C_STR[static_cast<int>(level)],
#if defined(SHIFT_JIS) && defined(_WIN32)
        utf8_to_sjis(message));
#else
        message);
#endif
    std::fputs(formatted_message.c_str(), stderr);
}

}  // namespace detail
