#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
  ares_channel channel;
  struct ares_addr_port_node *servers = NULL;
  int status;

  /* Initialize the ares library */
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  /* Initialize ares channel with default options */
  struct ares_options options;
  memset(&options, 0, sizeof(options));
  int optmask = 0;

  if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  /* Call the function-under-test */
  status = ares_get_servers_ports(&channel, &servers);

  /* Clean up */
  if (servers) {
    ares_free_data(servers);
  }
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}