// This fuzz driver is generated for library cares, aiming to fuzz the following functions:
// ares_library_init at ares_library_init.c:108:5 in ares.h
// ares_strerror at ares_strerror.c:30:13 in ares.h
// ares_init_options at ares_init.c:238:5 in ares.h
// ares_library_cleanup at ares_library_init.c:139:6 in ares.h
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static void dummy_callback(void *arg, int status, int timeouts, struct ares_addrinfo *res) {
    // Dummy callback for ares_getaddrinfo
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least one byte of data

    // Initialize c-ares library
    int flags = ARES_LIB_INIT_ALL;
    if (ares_library_init(flags) != ARES_SUCCESS) {
        return 0;
    }

    // Get error string
    const char *error_str = ares_strerror(Data[0]);
    (void)error_str; // Suppress unused variable warning

    // Initialize options
    struct ares_options options;
    memset(&options, 0, sizeof(options));
    options.flags = Data[0];
    ares_channel_t *channel;
    if (ares_init_options(&channel, &options, ARES_OPT_FLAGS) != ARES_SUCCESS) {
        ares_library_cleanup();
        return 0;
    }

    // Get error string again
    error_str = ares_strerror(Data[0]);
    (void)error_str; // Suppress unused variable warning

    // Get servers CSV
    char *servers_csv = ares_get_servers_csv(channel);
    if (servers_csv) {
        ares_free_string(servers_csv);
    }

    // Perform DNS resolution
    ares_getaddrinfo(channel, "example.com", NULL, NULL, dummy_callback, NULL);

    // Clean up
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}