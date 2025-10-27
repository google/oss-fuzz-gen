#include <stddef.h>
#include <stdint.h>

#include "dng_exceptions.h"
#include "dng_host.h"
#include "dng_info.h"
#include "dng_memory_stream.h"
#include "dng_negative.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  dng_host host;
  dng_memory_stream stream(host.Allocator());

  stream.Put(data, size);
  stream.SetReadPosition(0);

  std::unique_ptr<dng_negative> negative(host.Make_dng_negative());

  try {
    dng_info info;
    info.Parse(host, stream);
    info.PostParse(host);

    if (info.IsValidDNG()) {
      negative->Parse(host, stream, info);
      negative->PostParse(host, stream, info);
      negative->ReadStage1Image(host, stream, info);
    }
  } catch (dng_exception &e) {
    // dng_sdk throws C++ exceptions on errors
    // catch them here to prevent libFuzzer from crashing.
  }

  return 0;
}
