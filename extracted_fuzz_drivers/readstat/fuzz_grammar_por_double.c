#include <stdlib.h>

#include "../readstat.h"
#include "../spss/readstat_por_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  readstat_por_parse_double((const char *)Data, Size, NULL, NULL, NULL);
  return 0;
}
