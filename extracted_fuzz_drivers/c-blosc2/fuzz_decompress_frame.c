#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <blosc2.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int32_t i = 0, dsize = 0;
  int32_t nchunk = 0;

  blosc2_init();
  blosc2_set_nthreads(1);

  /* Create a super-chunk backed by an in-memory frame */
  blosc2_schunk *schunk = blosc2_schunk_from_buffer((uint8_t *)data, (int64_t)size, false);
  if (schunk == NULL) {
    blosc2_destroy();
    return 0;
  }
  /* Don't allow address sanitizer to allocate more than INT32_MAX */
  if (schunk->nbytes >= INT32_MAX) {
    blosc2_schunk_free(schunk);
    blosc2_destroy();
    return 0;
  }
  /* Decompress data */
  uint8_t *uncompressed_data = (uint8_t *)malloc((size_t)schunk->nbytes + 1);
  if (uncompressed_data != NULL) {
    for (i = 0, nchunk = 0; nchunk < schunk->nchunks - 1; nchunk++) {
      dsize = blosc2_schunk_decompress_chunk(schunk, nchunk, uncompressed_data + i, schunk->chunksize);
      if (dsize < 0) {
        printf("Decompression error.  Error code: %d\n", dsize);
        break;
      }
      i += dsize;
    }

    free(uncompressed_data);
  }

  blosc2_schunk_free(schunk);
  blosc2_destroy();
  return 0;
}

#ifdef __cplusplus
}
#endif
