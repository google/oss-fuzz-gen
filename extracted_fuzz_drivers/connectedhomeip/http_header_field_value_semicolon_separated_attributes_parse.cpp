#include "utility.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  SimpleWeb::HttpHeader::FieldValue::SemicolonSeparatedAttributes::parse(std::string(reinterpret_cast<const char *>(data), size));
  return 0;
}
