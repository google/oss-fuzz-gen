#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>

int LLVMFuzzerTestOneInput_5(const uint8_t* data, size_t size) {
  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Create a source channel */
  ares_channel src_channel = NULL;
  int status = ares_init(&src_channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Create a destination channel */
  ares_channel dest_channel = NULL;

  /* Call the function under test */
  ares_dup(&dest_channel, src_channel);

  /* Clean up */
  if (src_channel) {
    ares_destroy(src_channel);
  }
  if (dest_channel) {
    ares_destroy(dest_channel);
  }

  ares_library_cleanup();

  return 0;
}