#include <cstdint>

#include <Magick++.h>

#include "utils.cc"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const Magick::Blob blob(data, size);
  Magick::Image image;
  try {
    image.read(blob);
    image.enhance();
  } catch (Magick::Exception &e) {
  }

  return 0;
}
