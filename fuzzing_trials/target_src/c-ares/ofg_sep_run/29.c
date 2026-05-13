#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
  struct ares_uri_reply *uri_out = NULL;

  /* Call the function-under-test */
  ares_parse_uri_reply(data, (int)size, &uri_out);

  /* Free the allocated memory if any */
  if (uri_out) {
    ares_free_data(uri_out);
  }

  return 0;
}