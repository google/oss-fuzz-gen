#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of struct sip_msg is available
struct sip_msg {
    char *content;
    size_t length;
};

// Function-under-test
void reset_ua(const struct sip_msg *msg);

// Fuzzing harness
int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure there's at least some data to work with
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the sip_msg structure
    struct sip_msg msg;

    // Initialize the sip_msg structure
    msg.length = size;
    msg.content = (char *)malloc(size + 1);
    if (msg.content == NULL) {
        return 0; // Allocation failed, exit the test case
    }

    // Copy the fuzzing data into the sip_msg content
    memcpy(msg.content, data, size);
    msg.content[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    reset_ua(&msg);

    // Clean up
    free(msg.content);

    return 0;
}