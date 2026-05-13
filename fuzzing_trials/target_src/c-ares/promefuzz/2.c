// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_get_servers_csv at ares_update_servers.c:1314:7 in ares.h
// ares_free_string at ares_free_string.c:30:6 in ares.h
// ares_getaddrinfo at ares_getaddrinfo.c:695:6 in ares.h
// ares_destroy at ares_destroy.c:32:6 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ares.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void dummy_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
  // Dummy callback function
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;  // Ensure there's at least some data

    // Initialize the c-ares library
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        return 0;
    }

    // Get a human-readable error string
    const char *error_string = ares_strerror((int)Data[0]);

    // Initialize channel options
    struct ares_options options;
    memset(&options, 0, sizeof(options));
    options.timeout = 5000;  // Set timeout to 5000ms
    int optmask = ARES_OPT_TIMEOUT;

    ares_channel_t *channel = NULL;
    int status = ares_init_options(&channel, &options, optmask);

    // Get another human-readable error string
    error_string = ares_strerror(status);

    // Get DNS server list in CSV format
    char *servers_csv = ares_get_servers_csv(channel);

    // Free the CSV string if it was allocated
    if (servers_csv) {
        ares_free_string(servers_csv);
    }

    // Prepare to call ares_getaddrinfo
    struct ares_addrinfo_hints hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Dummy node and service for ares_getaddrinfo
    const char *node = "example.com";
    const char *service = "http";

    // Call ares_getaddrinfo
    ares_getaddrinfo(channel, node, service, &hints, dummy_callback, NULL);

    // Destroy the channel
    if (channel) {
        ares_destroy(channel);
    }

    // Cleanup the c-ares library
    ares_library_cleanup();

    return 0;
}