#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of struct sip_msg is available
struct sip_msg {
    char *buf;
    size_t len;
    // Other members of the struct can be added here as needed
};

// Function signature to be fuzzed
int parse_accept_hdr(const struct sip_msg *msg);

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the sip_msg structure
    struct sip_msg msg;
    msg.len = size;

    // Allocate memory for the buffer and copy the input data
    msg.buf = (char *)malloc(size + 1);
    if (msg.buf == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(msg.buf, data, size);
    msg.buf[size] = '\0'; // Null-terminate the buffer

    // Call the function-under-test
    parse_accept_hdr(&msg);

    // Free the allocated memory
    free(msg.buf);

    return 0;
}