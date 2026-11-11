#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
  if (size < sizeof(struct ares_addr)) {
    return 0; /* Not enough data to form a valid ares_addr structure */
  }

  struct ares_addr addr;
  memcpy(&addr, data, sizeof(struct ares_addr));

  // Call the function-under-test
  char *result = ares_dns_addr_to_ptr(&addr);

  // Free the result if it's not NULL
  if (result != NULL) {
    free(result);
  }

  return 0;
}

#ifdef __cplusplus
}
#endif