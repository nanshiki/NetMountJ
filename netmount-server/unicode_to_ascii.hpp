// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2025 Jaroslav Rohel, jaroslav.rohel@gmail.com

#ifndef _UNICODE_TO_ASCII_HPP_
#define _UNICODE_TO_ASCII_HPP_

#include <filesystem>
#include <string>

void load_transliteration_map(const std::filesystem::path & filepath);

#ifndef _WIN32
// Convert UTF-8 string to ASCII
std::string convert_utf8_to_ascii(const std::string & input);
#else
// Convert Windows UTF-16 string to ASCII
std::string convert_windows_unicode_to_ascii(const std::wstring & input);
#endif

#ifdef SHIFT_JIS
std::string sjis_to_utf8(const std::string src);
std::string utf8_to_sjis(const std::string src);
bool iskanji(unsigned char ch);
bool iskanji_position(unsigned char *buffer, int pos);
#endif

#endif
