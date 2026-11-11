#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming sip_msg is defined somewhere in the included headers
struct sip_msg {
    char *buf;
    size_t len;
};

// Function-under-test
int parse_orig_ruri(struct sip_msg *msg);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Allocate memory for the sip_msg structure
    struct sip_msg *msg = (struct sip_msg *)malloc(sizeof(struct sip_msg));
    if (msg == NULL) {
        return 0;
    }

    // Ensure that size is not zero to prevent unnecessary operations
    if (size == 0) {
        free(msg);
        return 0;
    }

    // Initialize the buf with the input data and set len to the size
    msg->buf = (char *)malloc(size + 1); // +1 for null-termination
    if (msg->buf == NULL) {
        free(msg);
        return 0;
    }
    memcpy(msg->buf, data, size);
    msg->buf[size] = '\0'; // Null-terminate the buffer
    msg->len = size;

    // Check if the buffer contains valid data for parse_orig_ruri
    // For example, ensure it starts with a valid SIP method or URI scheme
    // This is a placeholder check; adjust based on actual function requirements
    if (size < 4 || (strncmp(msg->buf, "sip:", 4) != 0 && strncmp(msg->buf, "sips:", 5) != 0)) {
        free(msg->buf);
        free(msg);
        return 0;
    }

    // Call the function-under-test
    parse_orig_ruri(msg);

    // Free the allocated memory
    free(msg->buf);
    free(msg);

    return 0;
}