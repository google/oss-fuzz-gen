#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
  /* Initialize ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Declare the channel before any code */
  ares_channel channel; // Use 'ares_channel' instead of 'ares_channel_t'
  
  /* Create a channel */
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Ensure the data is null-terminated for use as a string */
  char *local_dev_name = (char *)malloc(size + 1);
  if (local_dev_name == NULL) {
    ares_destroy(channel);
    return 0;
  }
  memcpy(local_dev_name, data, size);
  local_dev_name[size] = '\0';

  /* Call the function under test */
  ares_set_local_dev(channel, local_dev_name); // Pass 'channel' directly

  /* Clean up */
  free(local_dev_name);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}