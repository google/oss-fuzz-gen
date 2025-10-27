//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/diagnostics.hpp>

#include <boost/mysql/impl/internal/protocol/deserialization.hpp>

using namespace boost::mysql::detail;

static bool parse_auth_switch(const uint8_t *data, size_t size) noexcept {
  auth_switch msg{};
  auto ec = deserialize_auth_switch({data, size}, msg);
  return !ec.failed() && msg.auth_data.empty();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Note: this code should never throw exceptions, for any kind of input
  parse_auth_switch(data, size);
  return 0;
}
