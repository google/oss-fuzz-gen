#include <stdint.h>
#include <stdlib.h>

#include "blosc.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *const compressors[] = {"blosclz", "lz4", "lz4hc", "snappy", "zlib", "zstd"};
  int level = 9, filter = BLOSC_BITSHUFFLE, cindex = 0, i = 0;
  size_t nbytes, cbytes, blocksize;
  void *output, *input;

  blosc_set_nthreads(1);

  if (size > 0)
    level = data[0] % (9 + 1);
  if (size > 1)
    filter = data[1] % (BLOSC_BITSHUFFLE + 1);
  if (size > 2)
    cindex = data[2];

  /* Find next available compressor */
  while (blosc_set_compressor(compressors[cindex % 6]) == -1 && i < 6) {
    cindex++, i++;
  }
  if (i == 6) {
    /* No compressors available */
    return 0;
  }

  if (size > 3 && data[3] % 7 == 0)
    blosc_set_blocksize(4096);

  if (size > 4)
    blosc_set_splitmode(data[4] % BLOSC_FORWARD_COMPAT_SPLIT + 1);

  output = malloc(size + 1);
  if (output == NULL)
    return 0;

  if (blosc_compress(level, filter, 1, size, data, output, size) == 0) {
    /* Cannot compress src buffer into dest */
    free(output);
    return 0;
  }

  blosc_cbuffer_sizes(output, &nbytes, &cbytes, &blocksize);

  input = malloc(cbytes);
  if (input != NULL) {
    blosc_decompress(output, input, cbytes);
    free(input);
  }

  free(output);

  return 0;
}

#ifdef __cplusplus
}
#endif
