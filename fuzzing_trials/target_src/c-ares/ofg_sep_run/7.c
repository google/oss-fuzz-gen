#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_addr_port_node *servers = NULL;
  int status;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel */
  status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  ares_get_servers_ports(&channel, &servers);

  /* Clean up */
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