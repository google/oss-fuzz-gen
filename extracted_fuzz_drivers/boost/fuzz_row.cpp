//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/column_type.hpp>
#include <boost/mysql/field_view.hpp>
#include <boost/mysql/metadata.hpp>

#include <boost/mysql/detail/coldef_view.hpp>
#include <boost/mysql/detail/flags.hpp>
#include <boost/mysql/detail/resultset_encoding.hpp>

#include <boost/mysql/impl/internal/protocol/deserialization.hpp>

#include <boost/core/span.hpp>
#include <boost/endian/conversion.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>

using namespace boost::mysql::detail;
using boost::span;
using boost::mysql::column_type;
using boost::mysql::field_view;
using boost::mysql::metadata;

struct input {
  resultset_encoding encoding{resultset_encoding::text};
  std::vector<metadata> meta;
  span<const uint8_t> msg;
};

static input parse_input(const uint8_t *data, size_t size) {
  input res;
  res.msg = {data, size};
  const uint8_t *it = data;

  // Header[0][low 7 bits]: num_fields
  // Header[0][high bit]: encoding
  if (size < 1)
    return res;

  res.encoding = (*it & (1 << 7)) ? resultset_encoding::binary : resultset_encoding::text;
  size_t num_fields = *it & (0xff >> 1);
  ++it;

  // As many meta blocks as num_fields
  // meta[i] spans 2 bytes
  // meta[i][0][low 7 bits]: column_type
  // meta[i][0][high bit]: is unsigned flag
  // meta[i][1]: decimals
  size_t expected_size = 1 + 2 * num_fields;
  if (size < expected_size)
    return res;

  res.meta.reserve(num_fields);
  for (size_t i = 0; i < num_fields; ++i) {
    coldef_view coldef{};

    // Type: low 7 bits
    coldef.type = static_cast<column_type>(*it & (0xff >> 1));

    // Flags: we seed it with some value, and change the flag we're interested in
    coldef.flags = boost::endian::load_little_u16(data);
    if (*it & (1 << 7)) {
      coldef.flags |= column_flags::unsigned_;
    } else {
      coldef.flags &= ~column_flags::unsigned_;
    }
    ++it;

    // Decimals
    coldef.decimals = *it;
    ++it;

    // Done
    res.meta.push_back(access::construct<metadata>(coldef, false));
  }
  res.msg = {it, size - expected_size};
  return res;
}

static bool parse_row(const input &input) noexcept {
  size_t num_fields = input.meta.size();
  if (num_fields == 0u)
    return false;
  std::unique_ptr<field_view[]> fvs{new field_view[num_fields]};
  auto ec = deserialize_row(input.encoding, input.msg, input.meta, span<field_view>(fvs.get(), num_fields));
  if (ec.failed())
    return false;
  return num_fields > 0u && fvs[0].is_null();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  parse_row(parse_input(data, size));
  return 0;
}
