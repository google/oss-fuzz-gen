// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_init at ares_init.c:67:5 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_gethostbyname at ares_gethostbyname.c:99:6 in ares.h
// ares_set_servers at ares_update_servers.c:1221:5 in ares.h
// ares_cancel at ares_cancel.c:34:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>

static void dummy_callback(void *arg, int status, int timeouts, struct hostent *host) {
    (void)arg; (void)status; (void)timeouts; (void)host;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    ares_channel_t *channel;
    int status;
    struct ares_addr_node server;

    if (Size < sizeof(struct in_addr) + 1) {
        return 0;
    }

    // Initialize ares library
    status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    // Prepare server address
    server.family = AF_INET;
    memcpy(&server.addr.addr4, Data, sizeof(struct in_addr));
    server.next = NULL;

    // Ensure null-terminated string for hostname
    char *hostname = (char *)malloc(Size - sizeof(struct in_addr) + 1);
    if (!hostname) {
        ares_destroy(channel);
        return 0;
    }
    memcpy(hostname, Data + sizeof(struct in_addr), Size - sizeof(struct in_addr));
    hostname[Size - sizeof(struct in_addr)] = '\0';

    // Call the target functions
    ares_gethostbyname(channel, hostname, AF_INET, dummy_callback, NULL);
    ares_set_servers(channel, &server);
    ares_cancel(channel);

    // Cleanup
    free(hostname);
    ares_destroy(channel);
    return 0;
}