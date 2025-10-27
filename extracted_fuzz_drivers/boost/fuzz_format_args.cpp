//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/blob_view.hpp>
#include <boost/mysql/character_set.hpp>
#include <boost/mysql/datetime.hpp>
#include <boost/mysql/format_sql.hpp>
#include <boost/mysql/string_view.hpp>
#include <boost/mysql/time.hpp>

#include <boost/endian/conversion.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

using namespace boost::mysql;

namespace {

// Helper for parsing the input sample from the binary string provided by the fuzzer
// This follows a "never fail" approach
class sample_parser {
  const uint8_t *it_;
  const uint8_t *end_;

  std::size_t size() const noexcept { return static_cast<std::size_t>(end_ - it_); }

  template <class T> T get() {
    if (size() < sizeof(T))
      return T{};

    auto res = boost::endian::endian_load<T, sizeof(T), boost::endian::order::little>(it_);
    it_ += sizeof(T);
    return res;
  }

  blob_view get_blob() {
    std::size_t len = get<uint8_t>() % 128u;
    auto actual_len = (std::min)(len, size());
    blob_view res(it_, actual_len);
    it_ += actual_len;
    return res;
  }

  string_view get_string() {
    auto res = get_blob();
    return {reinterpret_cast<const char *>(res.data()), res.size()};
  }

  date get_date() { return date(get<uint16_t>(), get<uint8_t>(), get<uint8_t>()); }

  datetime get_datetime() { return datetime(get<uint16_t>(), get<uint8_t>(), get<uint8_t>(), get<uint8_t>(), get<uint8_t>(), get<uint8_t>(), get<uint32_t>()); }

  boost::mysql::time get_time() { return boost::mysql::time(get<int64_t>()); }

  format_arg get_format_arg(uint8_t type) {
    switch (type % 10) {
    case 0:
    default:
      return format_arg("", nullptr);
    case 1:
      return format_arg("", get<int64_t>());
    case 2:
      return format_arg("", get<uint64_t>());
    case 3:
      return format_arg("", get<float>());
    case 4:
      return format_arg("", get<double>());
    case 5:
      return format_arg("", get_string());
    case 6:
      return format_arg("", get_blob());
    case 7:
      return format_arg("", get_date());
    case 8:
      return format_arg("", get_datetime());
    case 9:
      return format_arg("", get_time());
    }
  }

public:
  sample_parser(const uint8_t *data, size_t size) noexcept : it_(data), end_(data + size) {}

  std::array<format_arg, 2> parse() {
    // Types
    uint8_t type_code = get<uint8_t>();
    uint8_t type0 = type_code & 0x0f;
    uint8_t type1 = type_code & 0xf0 >> 4;

    // Arguments
    return {{get_format_arg(type0), get_format_arg(type1)}};
  }
};

} // namespace

static bool call_format_sql(const uint8_t *data, size_t size) noexcept {
  // Parse the sample
  auto sample = sample_parser(data, size).parse();

  // Use a format context so we can avoid exceptions
  format_context ctx({utf8mb4_charset, true});
  format_sql_to(ctx, "{}, {}", {sample[0], sample[1]});

  return std::move(ctx).get().has_value();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  call_format_sql(data, size);
  return 0;
}
