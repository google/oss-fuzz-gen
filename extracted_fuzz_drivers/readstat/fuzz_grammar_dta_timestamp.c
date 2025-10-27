#include <stdlib.h>
#include <time.h>

#include "../readstat.h"
#include "../stata/readstat_dta_parse_timestamp.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct tm timestamp;
  dta_parse_timestamp((const char *)Data, Size, &timestamp, NULL, NULL);
  return 0;
}
