#include "utility.hpp"
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::stringstream ss;
  ss << std::string(reinterpret_cast<const char *>(data), size);
  SimpleWeb::HttpHeader::parse(ss);
  return 0;
}
