//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/character_set.hpp>
#include <boost/mysql/escape_string.hpp>
#include <boost/mysql/string_view.hpp>

#include <string>

using namespace boost::mysql;

static bool bit_set(uint8_t value, size_t bit) { return value & (0x01 << bit); }

static bool call_escape_string(const uint8_t *data, size_t size) noexcept {
  // We need at least 1 byte (for options)
  if (size < 1u)
    return false;
  const uint8_t *end = data + size;

  // Options
  bool backslash_slashes = bit_set(data[0], 0);
  auto quot_ctx = bit_set(data[0], 1) ? (bit_set(data[0], 2) ? quoting_context::double_quote : quoting_context::backtick) : quoting_context::single_quote;
  ++data;

  // String to escape
  string_view input(reinterpret_cast<const char *>(data), reinterpret_cast<const char *>(end));

  // Perform the escaping
  std::string escaped;
  error_code ec = escape_string(input, {utf8mb4_charset, backslash_slashes}, quot_ctx, escaped);
  return ec.failed() || escaped.empty();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  call_escape_string(data, size);
  return 0;
}
