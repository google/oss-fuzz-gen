#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the sip_msg structure is defined somewhere in the included headers
struct sip_msg {
    char *content;
    size_t length;
};

// Forward declaration of the function-under-test
int parse_accept_hdr(const struct sip_msg *msg);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to avoid empty content
    if (size == 0) {
        return 0;
    }

    // Allocate memory for sip_msg and its content
    struct sip_msg msg;
    msg.content = (char *)malloc(size + 1); // +1 for null-termination
    if (msg.content == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy data to msg.content and null-terminate it
    memcpy(msg.content, data, size);
    msg.content[size] = '\0';
    msg.length = size;

    // Call the function-under-test
    parse_accept_hdr(&msg);

    // Free allocated memory
    free(msg.content);

    return 0;
}