#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>
#include <limits.h>  // Include this to use INT_MAX

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
  /* Ensure that the data size is within the limits of an int */
  if (size > INT_MAX) {
    return 0;
  }

  /* Prepare the output parameter */
  struct ares_naptr_reply *naptr_out = NULL;

  /* Call the function under test */
  int result = ares_parse_naptr_reply(data, (int)size, &naptr_out);

  /* If naptr_out was allocated, free it */
  if (naptr_out) {
    ares_free_data(naptr_out);
  }

  return 0;
}