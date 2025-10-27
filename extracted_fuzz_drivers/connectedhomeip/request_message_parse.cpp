#include "utility.hpp"
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::stringstream ss;
  ss << std::string(reinterpret_cast<const char *>(data), size);
  std::string method, path, query_string, version;
  SimpleWeb::CaseInsensitiveMultimap header;
  SimpleWeb::RequestMessage::parse(ss, method, path, query_string, version, header);
  return 0;
}
