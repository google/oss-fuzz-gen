#include <stdlib.h>
#include <time.h>

#include "../readstat.h"
#include "../spss/readstat_sav_compress.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  unsigned char buffer[32768];
  struct sav_row_stream_s state = {.next_in = Data, .avail_in = Size, .next_out = buffer, .avail_out = sizeof(buffer)};
  sav_decompress_row(&state);
  return 0;
}
