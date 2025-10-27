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

    for (const auto format : formats) {
      char buffer[20]; // Small enough it should encounter overflows

      float f_val{};
      boost::charconv::from_chars(c_data, c_data + size, f_val, format);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), f_val, format);

      double val{};
      boost::charconv::from_chars(c_data, c_data + size, val, format);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), val, format);

#if BOOST_CHARCONV_LDBL_BITS == 64
      long double ld_val{};
      boost::charconv::from_chars(c_data, c_data + size, ld_val, format);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ld_val, format);
#endif

      // Also try with precisions
      for (int precision = -1; precision < 10; ++precision) {
        boost::charconv::to_chars(buffer, buffer + sizeof(buffer), f_val, format, precision);
        boost::charconv::to_chars(buffer, buffer + sizeof(buffer), val, format, precision);
#if BOOST_CHARCONV_LDBL_BITS == 64
        boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ld_val, format, precision);
#endif
      }
    }
  } catch (...) {
    std::cerr << "Error with: " << data << std::endl;
    std::terminate();
  }

  return 0;
}
