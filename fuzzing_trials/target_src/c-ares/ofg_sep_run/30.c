#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
  /* Ensure the size is within the range of an int */
  if (size > INT_MAX) {
    return 0;
  }

  struct ares_uri_reply *uri_out = NULL;

  /* Call the function-under-test */
  int result = ares_parse_uri_reply(data, (int)size, &uri_out);

  /* Free the allocated resources if the function succeeded */
  if (result == ARES_SUCCESS && uri_out != NULL) {
    ares_free_data(uri_out);
  }

  return 0;
}