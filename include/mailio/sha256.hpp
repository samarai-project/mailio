// Copyright (c) 2025
// SPDX-License-Identifier: MIT

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <stdexcept>

namespace mailio
{

/**
 * Compute SHA-256 digest for given bytes and return lowercase hex string.
 * Requires OpenSSL. If OpenSSL isn't available at build time, calling these
 * functions will throw std::runtime_error at runtime.
 */
std::string sha256_hex(std::string_view data);
std::string sha256_hex(const void* data, std::size_t size);
std::string sha256_hex(const std::vector<unsigned char>& data);

/**
 * Compute raw SHA-256 digest bytes.
 */
std::array<unsigned char, 32> sha256_bytes(std::string_view data);
std::array<unsigned char, 32> sha256_bytes(const void* data, std::size_t size);
std::array<unsigned char, 32> sha256_bytes(const std::vector<unsigned char>& data);

} // namespace mailio
