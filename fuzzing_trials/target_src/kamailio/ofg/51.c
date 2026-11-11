#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of sip_msg_t is available
typedef struct {
    char *body;
    size_t length;
} sip_msg_t;

// Function-under-test
char * get_body(const sip_msg_t *msg);

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to create a valid sip_msg_t
    }

    // Allocate memory for sip_msg_t and its body
    sip_msg_t msg;
    msg.length = size;
    msg.body = (char *)malloc(size + 1);

    if (msg.body == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy data into the body and null-terminate it
    memcpy(msg.body, data, size);
    msg.body[size] = '\0';

    // Call the function-under-test
    char *result = get_body(&msg);

    // Free allocated memory
    free(msg.body);

    // If result is not NULL, it is assumed to be dynamically allocated and should be freed
    if (result != NULL) {
        free(result);
    }

    return 0;
}