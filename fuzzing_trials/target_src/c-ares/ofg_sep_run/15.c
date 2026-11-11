#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Ensure the local_dev_name is null-terminated and non-NULL */
  char *local_dev_name = (char *)malloc(size + 1);
  if (local_dev_name == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(local_dev_name, data, size);
  local_dev_name[size] = '\0';

  /* Call the function-under-test */
  ares_set_local_dev(channel, local_dev_name);

  /* Clean up */
  free(local_dev_name);
  ares_destroy(channel);

  return 0;
}