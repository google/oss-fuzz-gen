#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <stdint.h>  // Include for uint8_t

int LLVMFuzzerTestOneInput_85(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_options options;
  int optmask = 0;
  int result;

  /* Initialize ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize channel */
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  result = ares_save_options(&channel, &options, &optmask);

  /* Clean up */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}