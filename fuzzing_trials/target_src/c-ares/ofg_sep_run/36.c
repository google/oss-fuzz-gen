#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C" {
#endif

// Callback function for ares_getnameinfo
static void nameinfo_callback(void *arg, int status, int timeouts, char *node, char *service) {
    (void)arg;      // Suppress unused parameter warning
    (void)status;   // Suppress unused parameter warning
    (void)timeouts; // Suppress unused parameter warning
    (void)node;     // Suppress unused parameter warning
    (void)service;  // Suppress unused parameter warning
}

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Initialize ares library
    ares_library_init(ARES_LIB_INIT_ALL);

    ares_channel channel;
    if (ares_init(&channel) != ARES_SUCCESS) {
        return 0;
    }

    // Create a sockaddr_in structure for testing
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(8080);
    if (size >= 4) {
        memcpy(&sa.sin_addr, data, 4);
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }

    ares_socklen_t salen = sizeof(sa);
    int flags_int = 0; // Use default flags
    void *arg = NULL;  // No additional argument needed for callback

    // Call the function-under-test
    ares_getnameinfo(channel, (struct sockaddr *)&sa, salen, flags_int, nameinfo_callback, arg);

    // Clean up
    ares_destroy(channel);
    ares_library_cleanup();

    return 0;
}

#ifdef __cplusplus
}
#endif