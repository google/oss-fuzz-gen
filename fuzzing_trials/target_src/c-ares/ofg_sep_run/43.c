#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
  struct ares_caa_reply *caa_out = NULL;

  /* Call the function-under-test */
  ares_parse_caa_reply(data, (int)size, &caa_out);

  /* Free the allocated resources if any */
  if (caa_out) {
    ares_free_data(caa_out);
  }

  return 0;
}