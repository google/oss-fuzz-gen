// Copyright (c) 2023, Paul Dreik
// Licensed under Boost software license 1.0
// SPDX-License-Identifier: BSL-1.0

#include <cstdint>
#include <cstring>
#include <exception>
#include <format>
#include <string_view>
#include <vector>

constexpr std::size_t fixed_size = 16;

struct LimitedIterator {
  using iterator_category = std::random_access_iterator_tag;
  using difference_type = std::ptrdiff_t;
  using value_type = char;
  using pointer = char *;
  using reference = char &;

  explicit LimitedIterator(char *ptr, std::size_t N) : m_ptr(ptr), m_N(N) {}
  // Prefix increment
  LimitedIterator &operator++() {
    if (m_N == 0)
      throw std::runtime_error("out of data");
    ++m_ptr;
    --m_N;
    return *this;
  }
  // Postfix increment
  LimitedIterator operator++(int) {
    if (m_N == 0)
      throw std::runtime_error("out of data");
    LimitedIterator tmp = *this;
    ++m_ptr;
    --m_N;
    return tmp;
  }
  char &operator*() { return *m_ptr; }
  char *m_ptr{};
  std::size_t m_N;
};

template <typename T> void invoke_fmt(const uint8_t *data, size_t size) {
  static_assert(sizeof(T) <= fixed_size, "fixed_size is too small");
  if (size <= fixed_size)
    return;
  T value{};
  if constexpr (std::is_same_v<bool, T>) {
    value = !!data[0];
  } else {
    std::memcpy(&value, data, sizeof(T));
  }

  data += fixed_size;
  size -= fixed_size;

  const auto *chardata = reinterpret_cast<const char *>(data);
  //  std::string format_string{ chardata, chardata + size };

  //  format_string.append(10, '}');
  const std::string_view format_string{chardata, size};

  try {
    std::vector<char> buf(2000);
    [[maybe_unused]] auto ignored = std::vformat_to(LimitedIterator(buf.data(), buf.size() - 2), format_string, std::make_format_args(value));
  } catch (std::exception &) {
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 3)
    return 0;

  try {

    const auto first = data[0];
    data++;
    size--;

    switch (first & 0xF) {
    case 0:
      invoke_fmt<bool>(data, size);
      break;
    case 1:
      invoke_fmt<char>(data, size);
      break;
    case 2:
      invoke_fmt<unsigned char>(data, size);
      break;
    case 3:
      invoke_fmt<signed char>(data, size);
      break;
    case 4:
      invoke_fmt<short>(data, size);
      break;
    case 5:
      invoke_fmt<unsigned short>(data, size);
      break;
    case 6:
      invoke_fmt<int>(data, size);
      break;
    case 7:
      invoke_fmt<unsigned int>(data, size);
      break;
    case 8:
      invoke_fmt<long>(data, size);
      break;
    case 9:
      invoke_fmt<unsigned long>(data, size);
      break;

    case 10:
      invoke_fmt<float>(data, size);
      break;
    case 11:
      invoke_fmt<double>(data, size);
      break;
    case 12:
      invoke_fmt<long double>(data, size);
      break;
    case 13:
      invoke_fmt<void *>(data, size);
      break;
    case 14:
      invoke_fmt<__int128_t>(data, size);
      break;
    case 15:
      invoke_fmt<__uint128_t>(data, size);
      break;
    }
  } catch (...) {
  }
  return 0;
}
