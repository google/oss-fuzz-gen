#include "grpc_transcoding/http_template.h"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string path((const char *)data, size);
  google::grpc::transcoding::HttpTemplate::Parse(path);
  return 0;
}
