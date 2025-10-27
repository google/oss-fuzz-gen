#include "utility.hpp"
#include <sstream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::stringstream ss;
  ss << std::string(reinterpret_cast<const char *>(data), size);
  std::string version, status_code;
  SimpleWeb::CaseInsensitiveMultimap header;
  SimpleWeb::ResponseMessage::parse(ss, version, status_code, header);
  return 0;
}
