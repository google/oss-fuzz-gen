#include <ares.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h> // Include this for uint8_t

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
  /* Initialize ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  ares_channel src_channel = NULL; // Correct type is ares_channel, not ares_channel_t
  ares_channel dest_channel = NULL; // Correct type is ares_channel, not ares_channel_t

  /* Initialize the source channel */
  int status = ares_init(&src_channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  ares_dup(&dest_channel, src_channel);

  /* Cleanup */
  if (src_channel) {
    ares_destroy(src_channel);
  }
  if (dest_channel) {
    ares_destroy(dest_channel);
  }

  /* Cleanup ares library */
  ares_library_cleanup();

  return 0;
}