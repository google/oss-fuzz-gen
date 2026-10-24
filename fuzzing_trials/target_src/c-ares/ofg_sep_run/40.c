#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
  /* Initialize ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  /* Create a channel */
  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Prepare timeval structures */
  struct timeval maxtv;
  struct timeval tvbuf;

  /* Initialize timeval structures with non-NULL values */
  maxtv.tv_sec = 1;
  maxtv.tv_usec = 0;
  tvbuf.tv_sec = 0;
  tvbuf.tv_usec = 0;

  /* Call the function-under-test */
  struct timeval *result = ares_timeout(channel, &maxtv, &tvbuf);

  /* Clean up the channel */
  ares_destroy(channel);

  /* Clean up ares library */
  ares_library_cleanup();

  return 0;
}