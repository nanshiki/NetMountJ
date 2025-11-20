// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#include "unicode_to_ascii.hpp"

#include "logger.hpp"

#include <cstdint>
#include <format>
#include <fstream>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

// Unicode to ASCII transliteration map
std::unordered_map<std::uint32_t, std::string> transliteration_map;


// Trim leading/trailing spaces and optional quotes
void clean_token(std::string_view & token) {
    // Trim whitespace
    auto start = token.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) {
        token = {};
        return;
    }
    auto end = token.find_last_not_of(" \t\r\n");

    // Remove surrounding quotes if present
    if (end - start >= 1 && token[start] == '"' && token[end] == '"') {
        ++start;
        --end;
    }

    token = token.substr(start, end - start + 1);
}


// Convert single UTF-8 character to Unicode codepoint
std::pair<std::uint32_t, bool> utf8_to_codepoint(std::string_view utf8_char) {
    const auto * const bytes = reinterpret_cast<const unsigned char *>(utf8_char.data());
    const auto len = utf8_char.size();

    if (len == 1) {
        return {bytes[0], true};
    }
    if ((bytes[0] & 0xE0) == 0xC0 && len >= 2) {
        return {((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F), true};
    }
    if ((bytes[0] & 0xF0) == 0xE0 && len >= 3) {
        return {((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F), true};
    }
    if ((bytes[0] & 0xF8) == 0xF0 && len >= 4) {
        return {
            ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) | ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F), true};
    }

    return {0xFFFD, false};  // Replacement char
}


#ifndef SHIFT_JIS
bool is_combining_mark(std::uint32_t cp) {
    // This covers the most-used combining ranges.
    return (cp >= 0x0300 && cp <= 0x036F) ||  // Combining Diacritical Marks
           (cp >= 0x1AB0 && cp <= 0x1AFF) ||  // Combining Diacritical Marks Extended
           (cp >= 0x1DC0 && cp <= 0x1DFF) ||  // Combining Diacritical Marks Supplement
           (cp >= 0x20D0 && cp <= 0x20FF) ||  // Combining Diacritical Marks for Symbols
           (cp >= 0xFE20 && cp <= 0xFE2F);    // Combining Half Marks
}
#endif

}  // namespace


void load_transliteration_map(const std::filesystem::path & filename) {
    std::ifstream file(filename);
    if (!file) {
        auto message = std::system_category().message(errno);
        throw std::runtime_error(
            std::format("Unable to open transliteration map file \"{}\": {}", filename.string(), message));
    }

    std::string line;
    size_t line_number = 0;

    while (std::getline(file, line)) {
        ++line_number;

        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            log(LogLevel::WARNING, "Missing ':' in file \"{}\" on line {}\n", filename.string(), line_number);
        }

        auto key = std::string_view(line.begin(), line.begin() + colon);
        auto value = std::string_view(line.begin() + colon + 1, line.end());
        clean_token(key);
        clean_token(value);

        if (key.empty()) {
            log(LogLevel::WARNING, "Empty key in file \"{}\" on line {}\n", filename.string(), line_number);
        }

        const auto [cp, is_ok] = utf8_to_codepoint(key);
        if (!is_ok) {
            log(LogLevel::WARNING, "Invalid UTF-8 key in file \"{}\" on line {}\n", filename.string(), line_number);
        }

        const auto [it, inserted] = transliteration_map.try_emplace(cp, value);
        if (!inserted && value != it->second) {
            log(LogLevel::WARNING,
                "The key '{}' in file \"{}\" on line {} has already been inserted with a different value\n",
                key,
                filename.string(),
                line_number);
        }
    }
}

#ifndef _WIN32
#include <iconv.h>

// Convert UTF-8 string to ASCII
std::string convert_utf8_to_ascii(const std::string & input) {
#ifdef SHIFT_JIS
    return utf8_to_sjis(input);
#else
    std::string result;

    for (size_t i = 0; i < input.size();) {
        const unsigned char c = input[i];
        size_t len = 1;
        if ((c & 0x80) == 0x00) {
            result += c;
        } else {
            if ((c & 0xE0) == 0xC0) {
                len = 2;
            } else if ((c & 0xF0) == 0xE0) {
                len = 3;
            } else if ((c & 0xF8) == 0xF0) {
                len = 4;
            } else {
                result += '_';
                ++i;
                continue;
            }

            if (i + len > input.size()) {
                break;
            }

            auto utf8_char = std::string_view(input.begin() + i, input.begin() + i + len);
            const auto [cp, is_ok] = utf8_to_codepoint(utf8_char);

            if (!is_combining_mark(cp)) {
                auto it = transliteration_map.find(cp);
                if (it != transliteration_map.end()) {
                    result += it->second;
                } else {
                    result += '_';
                }
            }
        }
        i += len;
    }

    return result;
#endif
}

#else
#include <Windows.h>

// Convert Windows UTF-16 string to ASCII
std::string convert_windows_unicode_to_ascii(const std::wstring & input) {
    std::string result;
#ifdef SHIFT_JIS
    int len = WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, NULL, 0, NULL, NULL);
    std::vector<char> dst(len + 1);
    WideCharToMultiByte(CP_ACP, 0, input.c_str(), -1, dst.data(), len, NULL, NULL);
    dst[len] = 0;
    result = dst.data();
#else
    for (size_t i = 0; i < input.size();) {
        const wchar_t wc = input[i];

        // Handle surrogate pair
        if (wc >= 0xD800 && wc <= 0xDBFF && (i + 1) < input.size()) {
            const wchar_t wc2 = input[i + 1];
            if (wc2 >= 0xDC00 && wc2 <= 0xDFFF) {
                const std::uint32_t cp = (((wc - 0xD800) << 10) | (wc2 - 0xDC00)) + 0x10000;
                if (!is_combining_mark(cp)) {
                    auto it = transliteration_map.find(cp);
                    if (it != transliteration_map.end()) {
                        result += it->second;
                    } else {
                        result += '_';
                    }
                }
                i += 2;
                continue;
            }
        }

        const auto cp = static_cast<std::uint32_t>(wc);
        if (cp <= 0x7F) {
            result += static_cast<char>(cp);
        } else if (!is_combining_mark(cp)) {
            auto it = transliteration_map.find(cp);
            if (it != transliteration_map.end()) {
                result += it->second;
            } else {
                result += '_';
            }
        }
        ++i;
    }
#endif
    return result;
}
#endif

#ifdef SHIFT_JIS
std::string sjis_to_utf8(const std::string src)
{
    std::string result;
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_OEMCP, 0, src.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wdst(len + 1);
    MultiByteToWideChar(CP_OEMCP, 0, src.c_str(), -1, wdst.data(), len);
    wdst[len] = 0;
    len = WideCharToMultiByte(CP_UTF8, 0, wdst.data(), -1, NULL, 0, NULL, NULL);
    std::vector<char> dst(len + 1);
    WideCharToMultiByte(CP_UTF8, 0, wdst.data(), -1, dst.data(), len, NULL, NULL);
    dst[len] = 0;
    result = dst.data();
#else
    iconv_t ic;

    if((ic = iconv_open("UTF-8", "CP932")) != (iconv_t)-1) {
        char *src_pt, *dst_pt;
        size_t src_length = src.length();
        size_t dst_length = src_length * 4;
        std::vector<char> dst(dst_length + 1);
        src_pt = const_cast<char *>(src.c_str());
        dst_pt = dst.data();
        iconv(ic, &src_pt, &src_length, &dst_pt, &dst_length);
        *dst_pt = 0;
        result = dst.data();
        iconv_close(ic);
    }
#endif
    return result;
}

std::string utf8_to_sjis(const std::string src)
{
    std::string result;
#ifdef _WIN32
    int len = MultiByteToWideChar(CP_UTF8, 0, src.c_str(), -1, NULL, 0);
    std::vector<WCHAR> wdst(len + 1);
    MultiByteToWideChar(CP_UTF8, 0, src.c_str(), -1, wdst.data(), len);
    wdst[len] = 0;
    len = WideCharToMultiByte(CP_OEMCP, 0, wdst.data(), -1, NULL, 0, NULL, NULL);
    std::vector<char> dst(len + 1);
    WideCharToMultiByte(CP_OEMCP, 0, wdst.data(), -1, dst.data(), len, NULL, NULL);
    dst[len] = 0;
    result = dst.data();
#else
    iconv_t ic;

    if((ic = iconv_open("CP932", "UTF-8")) != (iconv_t)-1) {
        char *src_pt, *dst_pt;
        size_t src_length = src.length();
        size_t dst_length = src_length * 4;
        std::vector<char> dst(dst_length + 1);
        src_pt = const_cast<char *>(src.c_str());
        dst_pt = dst.data();
        iconv(ic, &src_pt, &src_length, &dst_pt, &dst_length);
        *dst_pt = 0;
        result = dst.data();
        iconv_close(ic);
    }
#endif
    return result;
}

bool iskanji(unsigned char ch)
{
    if(((ch >= 0x81) && (ch <= 0x9f)) || ((ch >= 0xe0) && (ch <= 0xfc))) {
        return true;
    }
    return false;
}

bool iskanji_position(unsigned char *buffer, int pos)
{
    bool flag = false;
    while(pos > 0) {
        if(!flag) {
            if(iskanji(*buffer)) {
                flag = true;
            }
        } else {
            flag = false;
        }
        buffer++;
        pos--;
    }
    return flag;
}

bool ishalfkana(unsigned char ch)
{
    if(ch >= 0xa1 && ch <= 0xdf) {
        return true;
    }
    return false;
}

#endif

