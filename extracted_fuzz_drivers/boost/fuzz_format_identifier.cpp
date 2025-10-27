//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/character_set.hpp>
#include <boost/mysql/format_sql.hpp>
#include <boost/mysql/string_view.hpp>

#include <cstddef>
#include <cstdint>
#include <utility>

using namespace boost::mysql;

static bool call_format_sql(const uint8_t *data, size_t size) noexcept {
  // The entire string is our identifier
  string_view sample(reinterpret_cast<const char *>(data), size);

  // Use a format context so we can avoid exceptions
  format_context ctx({utf8mb4_charset, true});
  format_sql_to(ctx, "SELECT {:i};", sample);

  return std::move(ctx).get().has_value();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  call_format_sql(data, size);
  return 0;
}
