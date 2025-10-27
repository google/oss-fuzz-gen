#include <stdlib.h>
#include <time.h>

#include "../readstat.h"
#include "../sas/readstat_sas_rle.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  ssize_t compressed_len = sas_rle_compressed_len(Data, Size);
  if (compressed_len <= 0 || Size == 0)
    return 0;

  uint8_t *compressed = malloc(compressed_len);
  uint8_t *decompressed = malloc(Size);

  ssize_t actual_len = 0;

  if ((actual_len = sas_rle_compress(compressed, compressed_len, Data, Size)) != compressed_len) {
    printf("Unexpected compressed size (Expected: %ld  Got: %ld)\n", compressed_len, actual_len);
    __builtin_trap();
  }

  if ((actual_len = sas_rle_decompress(decompressed, Size, compressed, compressed_len)) != Size) {
    printf("Unexpected decompressed size (Expected: %ld  Got: %ld)\n", Size, actual_len);
    __builtin_trap();
  }

  if (memcmp(Data, decompressed, Size) != 0) {
    printf("Decompressed data doesn't match original\n");
    __builtin_trap();
  }

  free(compressed);
  free(decompressed);

  return 0;
}
