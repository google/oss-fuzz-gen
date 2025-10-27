// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#include <boost/charconv.hpp>
#include <boost/core/detail/string_view.hpp>
#include <exception>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  try {
    auto c_data = reinterpret_cast<const char *>(data);

    const auto formats = {boost::charconv::chars_format::general, boost::charconv::chars_format::fixed, boost::charconv::chars_format::scientific, boost::charconv::chars_format::hex};

    boost::core::string_view sv{c_data, size};

    for (const auto format : formats) {
      float f_val;
      boost::charconv::from_chars(c_data, c_data + size, f_val, format);
      boost::charconv::from_chars(sv, f_val, format);

      double val;
      boost::charconv::from_chars(c_data, c_data + size, val, format);
      boost::charconv::from_chars(sv, val, format);

      long double ld_val;
      boost::charconv::from_chars(c_data, c_data + size, ld_val, format);
      boost::charconv::from_chars(sv, ld_val, format);
    }
  } catch (...) {
    std::cerr << "Error with: " << data << std::endl;
    std::terminate();
  }

  return 0;
}
