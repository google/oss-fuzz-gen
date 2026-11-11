#include <ares.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;

  /* Initialize the ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize a channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function under test */
  if (size > 0) {
    ares_reinit(&channel);
  }

  /* Clean up the channel */
  ares_destroy(channel);

  /* Clean up the ares library */
  ares_library_cleanup();

  return 0;
}

#ifdef __cplusplus
}
#endif