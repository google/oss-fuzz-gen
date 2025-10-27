#include <stdlib.h>
#include <time.h>

#include "../readstat.h"
#include "../sas/readstat_xport.h"
#include "../sas/readstat_xport_parse_format.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  xport_format_t format;
  xport_parse_format((const char *)Data, Size, &format, NULL, NULL);
  return 0;
}
