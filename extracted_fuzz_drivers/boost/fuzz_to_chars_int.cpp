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

    for (int base = 2; base < 36; ++base) {
      char buffer[10]; // Small enough it should force overflows

      char c_val{};
      boost::charconv::from_chars(c_data, c_data + size, c_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), c_val, base);

      int i_val{};
      boost::charconv::from_chars(c_data, c_data + size, i_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), i_val, base);

      long l_val{};
      boost::charconv::from_chars(c_data, c_data + size, l_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), l_val, base);

      long long ll_val{};
      boost::charconv::from_chars(c_data, c_data + size, ll_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ll_val, base);

      unsigned char uc_val{};
      boost::charconv::from_chars(c_data, c_data + size, uc_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), uc_val, base);

      unsigned int ui_val{};
      boost::charconv::from_chars(c_data, c_data + size, ui_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ui_val, base);

      unsigned long ul_val{};
      boost::charconv::from_chars(c_data, c_data + size, ul_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ul_val, base);

      unsigned long long ull_val{};
      boost::charconv::from_chars(c_data, c_data + size, ull_val, base);
      boost::charconv::to_chars(buffer, buffer + sizeof(buffer), ull_val, base);
    }
  } catch (...) {
    std::cerr << "Error with: " << data << std::endl;
    std::terminate();
  }

  return 0;
}
