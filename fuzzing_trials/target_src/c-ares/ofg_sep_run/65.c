#include <stddef.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
  struct ares_naptr_reply *naptr_out = NULL;

  /* Call the function-under-test */
  ares_parse_naptr_reply(data, (int)size, &naptr_out);

  /* Free the allocated naptr_out if it was successfully populated */
  if (naptr_out) {
    ares_free_data(naptr_out);
  }

  return 0;
}