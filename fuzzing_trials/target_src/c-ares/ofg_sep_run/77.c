#include <stddef.h>
#include <stdlib.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_77(const unsigned char *data, size_t size) {
  ares_channel channel;
  struct ares_addr_node *servers = NULL;
  int status;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Create a channel with default options */
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  status = ares_get_servers(channel, &servers);

  /* Clean up resources */
  if (servers != NULL) {
    ares_free_data(servers);
  }
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}

#ifdef __cplusplus
}
#endif