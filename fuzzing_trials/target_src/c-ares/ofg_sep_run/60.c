#include <stddef.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
  struct ares_mx_reply *mx = NULL;

  /* Call the function-under-test with the provided data */
  ares_parse_mx_reply(data, (int)size, &mx);

  /* Free the allocated memory if mx is not NULL */
  if (mx) {
    ares_free_data(mx);
  }

  return 0;
}