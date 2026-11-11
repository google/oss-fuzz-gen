#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_38(const uint8_t *data, size_t size) {
  /* Ensure that the size is sufficient for the function to process */
  if (size == 0) {
    return 0;
  }

  struct ares_srv_reply *srv = NULL;

  /* Call the function-under-test */
  int result = ares_parse_srv_reply(data, (int)size, &srv);

  /* Free the allocated srv structure if it was successfully parsed */
  if (result == ARES_SUCCESS && srv != NULL) {
    ares_free_data(srv);
  }

  return 0;
}