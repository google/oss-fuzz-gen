//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/character_set.hpp>

#include <boost/mysql/impl/internal/call_next_char.hpp>

#include <cstddef>
#include <stdint.h>

using namespace boost::mysql;

static bool iterate_utf8mb4_string(const uint8_t *data, size_t size) noexcept {
  const char *it = reinterpret_cast<const char *>(data);
  const char *last = it + size;

  while (it < last) {
    std::size_t char_len = detail::call_next_char(utf8mb4_charset, it, last);
    if (char_len == 0u)
      return false; // Invalid character
    it += char_len;
  }

  return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  iterate_utf8mb4_string(data, size);
  return 0;
}
