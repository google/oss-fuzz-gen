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
    boost::core::string_view sv{c_data, size};

    for (int base = 2; base < 36; ++base) {
      char c_val;
      boost::charconv::from_chars(c_data, c_data + size, c_val, base);
      boost::charconv::from_chars(sv, c_val, base);

      int i_val;
      boost::charconv::from_chars(c_data, c_data + size, i_val, base);
      boost::charconv::from_chars(sv, i_val, base);

      long l_val;
      boost::charconv::from_chars(c_data, c_data + size, l_val, base);
      boost::charconv::from_chars(sv, l_val, base);

      long long ll_val;
      boost::charconv::from_chars(c_data, c_data + size, ll_val, base);
      boost::charconv::from_chars(sv, ll_val, base);

      unsigned char uc_val;
      boost::charconv::from_chars(c_data, c_data + size, uc_val, base);
      boost::charconv::from_chars(sv, uc_val, base);

      unsigned int ui_val;
      boost::charconv::from_chars(c_data, c_data + size, ui_val, base);
      boost::charconv::from_chars(sv, ui_val, base);

      unsigned long ul_val;
      boost::charconv::from_chars(c_data, c_data + size, ul_val, base);
      boost::charconv::from_chars(sv, ul_val, base);

      unsigned long long ull_val;
      boost::charconv::from_chars(c_data, c_data + size, ull_val, base);
      boost::charconv::from_chars(sv, ull_val, base);
    }
  } catch (...) {
    std::cerr << "Error with: " << data << std::endl;
    std::terminate();
  }

  return 0;
}
