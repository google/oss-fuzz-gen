#include <stdlib.h>
#include <time.h>

#include "../readstat.h"
#include "../spss/readstat_spss.h"
#include "../spss/readstat_spss_parse.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  spss_format_t format;
  spss_parse_format((const char *)Data, Size, &format);
  return 0;
}
