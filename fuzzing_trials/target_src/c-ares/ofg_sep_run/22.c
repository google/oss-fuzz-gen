#include <ares.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
  ares_channel channel; // Corrected type name
  int status;
  int timeout_ms;

  /* Initialize the ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize the channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Use the first byte of data as an integer for timeout_ms */
  if (size > 0) {
    timeout_ms = (int)data[0];
  } else {
    timeout_ms = 100; // default value if no data is provided
  }

  /* Call the function-under-test */
  ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

  /* Cleanup */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}

#ifdef __cplusplus
}
#endif