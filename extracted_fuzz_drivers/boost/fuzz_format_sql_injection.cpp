//
// Copyright (c) 2019-2024 Ruben Perez Hidalgo (rubenperez038 at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <boost/mysql/any_connection.hpp>
#include <boost/mysql/connect_params.hpp>
#include <boost/mysql/format_sql.hpp>
#include <boost/mysql/results.hpp>
#include <boost/mysql/ssl_mode.hpp>

#include <boost/asio/io_context.hpp>

#include <cstddef>
#include <stdexcept>

#include "test_common/ci_server.hpp"

using namespace boost::mysql;
namespace asio = boost::asio;

// Fuzzes format_sql in an attempt to find SQL injection vulnerabilities.
// This is not a usual fuzzer, as it sends the generated SQL to a real server -
// this is the only way to be truly sure that no injection took place

namespace {

class fuzzer {
  asio::io_context ctx_;
  any_connection conn_;

public:
  fuzzer() : conn_(ctx_) {
    connect_params params{
        host_and_port{test::get_hostname()},
        test::integ_user,
        test::integ_passwd,
        test::integ_db,
    };
    params.ssl = ssl_mode::disable;
    conn_.connect(params);
  }

  int test(const uint8_t *data, size_t size) {
    // Create the query
    format_context ctx(conn_.format_opts().value());
    format_sql_to(ctx, "SELECT id FROM three_rows_table WHERE field_varchar = {}", string_view(reinterpret_cast<const char *>(data), size));
    auto query = std::move(ctx).get();

    // If the generated query contains an error, the input wasn't valid UTF-8 - reject the sample
    if (query.has_error())
      return -1;

    // Execute it
    results r;
    conn_.execute(*query, r);

    // Check that we didn't get excess data
    auto retrieved_rows = r.rows().size();
    if (retrieved_rows != 1u && retrieved_rows != 0u)
      throw std::runtime_error("Retrieved more rows than expected");

    return 0;
  }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static fuzzer f;
  return f.test(data, size);
}
