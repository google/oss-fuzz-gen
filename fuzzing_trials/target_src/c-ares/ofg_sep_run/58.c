#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
  ares_channel channel;
  int status;

  /* Initialize ares library */
  status = ares_library_init(ARES_LIB_INIT_ALL);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel */
  struct ares_options options;
  int optmask = 0;
  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function under test */
  char *servers_csv = ares_get_servers_csv(channel);
  if (servers_csv) {
    ares_free_data(servers_csv);
  }

  /* Cleanup */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}