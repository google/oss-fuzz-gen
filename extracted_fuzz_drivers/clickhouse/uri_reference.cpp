//
// Copyright (c) 2023 alandefreitas (alandefreitas@gmail.com)
//
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//

#include <boost/core/detail/string_view.hpp>
#include <boost/core/ignore_unused.hpp>
#include <boost/url/parse.hpp>

using namespace boost::urls;
namespace core = boost::core;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  core::string_view s{reinterpret_cast<const char *>(data), size};
  boost::ignore_unused(parse_uri_reference(s));
  return 0;
}
