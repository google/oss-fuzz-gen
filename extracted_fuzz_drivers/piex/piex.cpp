/* By Guido Vranken <guidovranken@gmail.com> */

#include "src/piex.h"
#include "fuzzing/datasource/datasource.hpp"
#include "shared.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzingStreamInterface stream(std::vector<uint8_t>(data, data + size));
  piex::PreviewImageData preview_image_data;
  piex::GetPreviewImageData(&stream, &preview_image_data);
  return 0;
}
