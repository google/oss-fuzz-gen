#include <stdint.h>
#include <stdlib.h>

#include "blosc.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  size_t nbytes, cbytes, blocksize;
  void *output;

  if (size < BLOSC_MIN_HEADER_LENGTH) {
    return 0;
  }

  blosc_cbuffer_sizes(data, &nbytes, &cbytes, &blocksize);
  if (cbytes != size) {
    return 0;
  }
  if (nbytes == 0) {
    return 0;
  }

  if (blosc_cbuffer_validate(data, size, &nbytes) != 0) {
    /* Unexpected nbytes specified in blosc header */
    return 0;
  }

  output = malloc(cbytes);
  if (output != NULL) {
    blosc_decompress(data, output, cbytes);
    free(output);
  }
  return 0;
}

#ifdef __cplusplus
}
#endif
