#include <cstdint>

#include <Magick++.h>

#include "utils.cc"

#define FUZZ_CODER_STRING_LITERAL_X(name) FUZZ_CODER_STRING_LITERAL(name)
#define FUZZ_CODER_STRING_LITERAL(name) #name

#define FUZZ_CODER FUZZ_CODER_STRING_LITERAL_X(FUZZ_GRAPHICSMAGICK_CODER)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  Magick::Image image;
  std::string coder = FUZZ_CODER;
  image.magick(coder);
  image.fileName(coder + ":");
  // Add an arbitary limit on JPEG scan lines
  image.defineValue("JPEG", "max-scan-number", "50");
  const Magick::Blob blob(data, size);
  try {
    image.read(blob);
  } catch (Magick::Exception &e) {
    return 0;
  }

#if FUZZ_GRAPHICSMAGICK_CODER_WRITE
  Magick::Blob outBlob;
  try {
    image.write(&outBlob, coder);
  } catch (Magick::Exception &e) {
  }
#endif

  return 0;
}
