// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_init at ares_init.c:67:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
// ares_set_servers_ports at ares_update_servers.c:1245:5 in ares.h
// ares_gethostbyname at ares_gethostbyname.c:99:6 in ares.h
// ares_set_servers_ports at ares_update_servers.c:1245:5 in ares.h
// ares_cancel at ares_cancel.c:34:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

static void host_callback(void *arg, int status, int timeouts, struct hostent *host) {
    // Dummy callback function
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    
    ares_channel_t *channel;
    int status;
    struct ares_addr_port_node servers;
    char hostname[256];

    // Initialize the ares library
    status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Initialize the channel
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Setup server address and ports
    memset(&servers, 0, sizeof(servers));
    servers.family = AF_INET;
    servers.addr.addr4.s_addr = htonl(INADDR_LOOPBACK);
    servers.udp_port = htons(53);
    servers.tcp_port = htons(53);

    // Call ares_set_servers_ports
    ares_set_servers_ports(channel, &servers);

    // Prepare a hostname from the fuzz data
    size_t hostname_len = Size > 255 ? 255 : Size;
    memcpy(hostname, Data, hostname_len);
    hostname[hostname_len] = '\0';

    // Call ares_gethostbyname
    ares_gethostbyname(channel, hostname, AF_INET, host_callback, NULL);

    // Call ares_set_servers_ports again
    ares_set_servers_ports(channel, &servers);

    // Call ares_cancel to cancel all queries
    ares_cancel(channel);

    // Cleanup
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}