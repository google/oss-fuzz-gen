#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// Assuming socket_t is defined somewhere in the included headers
typedef int socket_t;

// Placeholder function signature for netlib_connectsock
socket_t netlib_connectsock(int, const char *, const char *, const char *);

// Helper function to convert a portion of data to a null-terminated string
void extract_string(const uint8_t *data, size_t size, char *output, size_t max_len) {
    size_t len = size < max_len - 1 ? size : max_len - 1;
    memcpy(output, data, len);
    output[len] = '\0';
}

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;  // Not enough data to extract meaningful parameters
    }

    // Extract integer parameter
    int int_param = (int)data[0];

    // Extract string parameters
    char str1[256];
    char str2[256];
    char str3[256];

    size_t offset = 1;
    size_t remaining_size = size - offset;

    extract_string(data + offset, remaining_size, str1, sizeof(str1));
    offset += strlen(str1) + 1;
    remaining_size = size > offset ? size - offset : 0;

    extract_string(data + offset, remaining_size, str2, sizeof(str2));
    offset += strlen(str2) + 1;
    remaining_size = size > offset ? size - offset : 0;

    extract_string(data + offset, remaining_size, str3, sizeof(str3));

    // Call the function-under-test
    socket_t result = netlib_connectsock(int_param, str1, str2, str3);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

    return 0;
}