#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of struct sip_msg is available
struct sip_msg {
    char *buffer;
    size_t len;
    // Other fields...
};

// Forward declaration of the function-under-test
int parse_to_header(const struct sip_msg *msg);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure we have a non-zero size for the buffer
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the sip_msg structure
    struct sip_msg msg;
    msg.len = size;
    msg.buffer = (char *)malloc(size + 1); // +1 for null-terminator

    if (msg.buffer == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy the input data to the buffer and null-terminate it
    memcpy(msg.buffer, data, size);
    msg.buffer[size] = '\0';

    // Call the function-under-test
    int result = parse_to_header(&msg);

    // Free allocated memory
    free(msg.buffer);

    return 0;
}

#ifdef __cplusplus
}
#endif