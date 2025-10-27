//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/impl/internal/protocol/deserialization.hpp>

using namespace boost::mysql::detail;

static bool parse_err_packet(const uint8_t *data, size_t size) noexcept {
  err_view msg{};
  auto ec = deserialize_error_packet({data, size}, msg);
  return !ec.failed() && msg.error_code;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  parse_err_packet(data, size);
  return 0;
}
