#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming net_link_type is an enum or typedef defined elsewhere
typedef enum {
    NET_LINK_TYPE_UNKNOWN,
    NET_LINK_TYPE_GNSS,
    NET_LINK_TYPE_OTHER
} net_link_type;

// Mock implementation of the function-under-test
net_link_type netgnss_uri_type_17(const char *uri) {
    if (uri == NULL) {
        return NET_LINK_TYPE_UNKNOWN;
    }
    if (strncmp(uri, "gnss://", 7) == 0) {
        return NET_LINK_TYPE_GNSS;
    }
    return NET_LINK_TYPE_OTHER;
}

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Ensure the input data is null-terminated
    char *uri = (char *)malloc(size + 1);
    if (uri == NULL) {
        return 0;
    }
    memcpy(uri, data, size);
    uri[size] = '\0';

    // Call the function-under-test
    net_link_type type = netgnss_uri_type_17(uri);

    // Print the result (for debugging purposes)
    printf("URI: %s, Type: %d\n", uri, type);

    // Clean up
    free(uri);

    return 0;
}