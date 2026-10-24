#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <arpa/inet.h>  /* Include for AF_INET and struct in_addr */

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
  ares_channel channel;  // Corrected type from ares_channel_t to ares_channel
  int status = ares_init(&channel);
  if (status != ARES_SUCCESS) {
    return 0;
  }

  /* Allocate memory for servers */
  struct ares_addr_port_node *servers = (struct ares_addr_port_node *)malloc(sizeof(struct ares_addr_port_node));
  if (!servers) {
    ares_destroy(channel);
    return 0;
  }

  /* Initialize servers with some non-NULL values */
  servers->next = NULL;
  servers->family = AF_INET;
  if (size >= sizeof(struct in_addr)) {
    memcpy(&servers->addr.addr4, data, sizeof(struct in_addr));
  } else {
    memset(&servers->addr.addr4, 0, sizeof(struct in_addr));
  }
  servers->udp_port = 53;
  servers->tcp_port = 53;

  /* Call the function-under-test */
  ares_set_servers_ports(&channel, servers);

  /* Clean up */
  free(servers);
  ares_destroy(channel);

  return 0;
}