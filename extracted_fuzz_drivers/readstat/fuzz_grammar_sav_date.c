#include <stdlib.h>
#include <time.h>

#include "../readstat.h"

#include "../spss/readstat_sav_parse_timestamp.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  struct tm timestamp;
  sav_parse_date((const char *)Data, Size, &timestamp, NULL, NULL);
  return 0;
}
