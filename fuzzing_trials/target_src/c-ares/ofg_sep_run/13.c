#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h> // For AF_INET

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
  /* Initialize the ares library */
  ares_library_init(ARES_LIB_INIT_ALL);

  ares_channel channel;
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Create a dummy ares_addr_port_node structure */
  struct ares_addr_port_node server_node;
  memset(&server_node, 0, sizeof(server_node));

  /* Set some non-NULL values */
  server_node.family = AF_INET;
  server_node.udp_port = 53;
  server_node.tcp_port = 53;

  /* Create a dummy IP address */
  uint8_t ip[4] = {127, 0, 0, 1};
  memcpy(&server_node.addr.addr4, ip, sizeof(ip));

  /* Call the function under test */
  ares_set_servers_ports(&channel, &server_node);

  /* Clean up */
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}