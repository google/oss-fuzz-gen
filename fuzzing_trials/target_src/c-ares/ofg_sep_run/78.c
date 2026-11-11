#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

extern int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_addr_node *servers = NULL;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel with default options */
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  int result = ares_get_servers(&channel, &servers);

  /* Free any allocated server nodes */
  if (servers != NULL) {
    ares_free_data(servers);
  }

  /* Cleanup ares channel */
  ares_destroy(channel);

  /* Cleanup ares library */
  ares_library_cleanup();

  return 0;
}