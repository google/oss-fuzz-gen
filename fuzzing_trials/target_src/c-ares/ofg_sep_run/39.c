#include <stddef.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
  struct ares_srv_reply *srv_out = NULL;

  /* Call the function-under-test */
  ares_parse_srv_reply(data, (int)size, &srv_out);

  /* Free the allocated memory if any */
  if (srv_out) {
    ares_free_data(srv_out);
  }

  return 0;
}