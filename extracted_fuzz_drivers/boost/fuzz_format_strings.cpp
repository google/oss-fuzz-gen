//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/character_set.hpp>
#include <boost/mysql/constant_string_view.hpp>
#include <boost/mysql/datetime.hpp>
#include <boost/mysql/format_sql.hpp>
#include <boost/mysql/string_view.hpp>

using namespace boost::mysql;

// This fuzzer focuses on format string parsing, rather than argument formatting
static bool call_format_sql(const uint8_t *data, size_t size) noexcept {
  // The format string is the entire input
  string_view format_str(reinterpret_cast<const char *>(data), size);

  // Use a format context to avoid exceptions
  format_context ctx({utf8mb4_charset, true});

  // Call format with some arguments
  format_sql_to(ctx, runtime(format_str),
                // clang-format off
        {
            {"name", "A\\ 'val'"        },
            {"val",  date(2021, 10, 1)  },
            {"k",    42                 },
            {"k2",   10.0               },
            {"null", nullptr            },
        } // clang-format on
  );

  return std::move(ctx).get().has_value();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  call_format_sql(data, size);
  return 0;
}
