#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h> // Include limits.h for INT_MAX
#include "ares.h"

int LLVMFuzzerTestOneInput_61(const unsigned char *data, size_t size) {
  /* Ensure that size is within the bounds of an int */
  if (size > INT_MAX) {
    return 0;
  }

  struct ares_mx_reply *mx_out = NULL;

  /* Call the function-under-test */
  int result = ares_parse_mx_reply(data, (int)size, &mx_out);

  /* Free the allocated memory if the parsing was successful */
  if (result == ARES_SUCCESS && mx_out != NULL) {
    ares_free_data(mx_out);
  }

  return 0;
}