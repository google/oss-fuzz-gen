#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  ares_channel channel;
  struct ares_options options;
  int optmask = 0;

  /* Initialize the ares channel */
  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Allocate memory for socks */
  int numsocks = ARES_GETSOCK_MAXNUM;
  ares_socket_t socks[ARES_GETSOCK_MAXNUM];

  /* Call the function-under-test */
  ares_getsock(channel, socks, numsocks);

  /* Clean up the ares channel */
  ares_destroy(channel);

  /* Clean up the ares library */
  ares_library_cleanup();

  return 0;
}