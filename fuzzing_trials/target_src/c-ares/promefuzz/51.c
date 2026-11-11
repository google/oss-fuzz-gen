// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_set_servers_ports at ares_update_servers.c:1246:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_gethostbyname at ares_gethostbyname.c:99:6 in ares.h
// ares_set_servers_ports at ares_update_servers.c:1246:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_cancel at ares_cancel.c:34:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>

static void host_callback(void *arg, int status, int timeouts, const struct hostent *host) {
  (void)arg;
  (void)status;
  (void)timeouts;
  (void)host;
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
  ares_channel_t *channel;
  struct ares_addr_port_node server;
  int result;

  if (Size < sizeof(struct ares_addr_port_node) + 1) {
    return 0;
  }

  // Initialize server address and ports
  memcpy(&server, Data, sizeof(struct ares_addr_port_node));
  server.next = NULL;

  // Initialize ares library
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  // Create a channel
  if (ares_init(&channel) != ARES_SUCCESS) {
    ares_library_cleanup();
    return 0;
  }

  // First call to ares_set_servers_ports
  result = ares_set_servers_ports(channel, &server);
  if (result != ARES_SUCCESS) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  // Ensure the hostname is null-terminated to prevent overflow
  char *hostname = (char *)malloc(Size - sizeof(struct ares_addr_port_node) + 1);
  if (!hostname) {
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }
  memcpy(hostname, Data + sizeof(struct ares_addr_port_node), Size - sizeof(struct ares_addr_port_node));
  hostname[Size - sizeof(struct ares_addr_port_node)] = '\0';

  // Call to ares_gethostbyname
  ares_gethostbyname(channel, hostname, AF_INET, host_callback, NULL);

  // Second call to ares_set_servers_ports
  result = ares_set_servers_ports(channel, &server);
  if (result != ARES_SUCCESS) {
    free(hostname);
    ares_destroy(channel);
    ares_library_cleanup();
    return 0;
  }

  // Call to ares_cancel
  ares_cancel(channel);

  // Cleanup
  free(hostname);
  ares_destroy(channel);
  ares_library_cleanup();

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
