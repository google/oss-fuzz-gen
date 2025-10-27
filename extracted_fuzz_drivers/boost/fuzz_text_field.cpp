//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/column_type.hpp>
#include <boost/mysql/field_view.hpp>
#include <boost/mysql/metadata.hpp>
#include <boost/mysql/string_view.hpp>

#include <boost/mysql/detail/coldef_view.hpp>
#include <boost/mysql/detail/flags.hpp>

#include <boost/mysql/impl/internal/protocol/deserialization.hpp>

#include <boost/endian/conversion.hpp>

#include <cstddef>
#include <cstdint>

using namespace boost::mysql::detail;
using boost::mysql::column_type;
using boost::mysql::field_view;
using boost::mysql::metadata;
using boost::mysql::string_view;

struct input {
  metadata meta;
  string_view msg;
};

static string_view sv_from_range(const uint8_t *data, size_t size) { return string_view(reinterpret_cast<const char *>(data), size); }

static input parse_input(const uint8_t *data, size_t size) {
  // Samples have a 2-byte header specifying metadata
  // meta[0][low 7 bits]: column_type
  // meta[0][high bit]: is unsigned flag
  // meta[1]: decimals
  if (size < 2)
    return input{metadata(), sv_from_range(data, size)};

  coldef_view coldef{};

  // Type: low 7 bits
  coldef.type = static_cast<column_type>(data[0] & (0xff >> 1));

  // Flags: we seed it with some value, and change the flag we're interested in
  coldef.flags = boost::endian::load_little_u16(size >= 4 ? data + 2 : data);
  if (data[0] & (1 << 7)) {
    coldef.flags |= column_flags::unsigned_;
  } else {
    coldef.flags &= ~column_flags::unsigned_;
  }

  // Decimals
  coldef.decimals = data[1];

  // Done
  return {
      access::construct<metadata>(coldef, false),
      sv_from_range(data + 2, size - 2),
  };
}

static bool parse_field(const input &input) noexcept {
  field_view fv;
  auto ec = deserialize_text_field(input.msg, input.meta, fv);
  if (ec != deserialize_errc::ok)
    return false;
  return !fv.is_null();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  parse_field(parse_input(data, size));
  return 0;
}
