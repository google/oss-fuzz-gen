#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/kamailio/src/core/parser/parse_via.h" // Include the header for parse_via_header function

// Assuming the definitions of sip_msg and via_body are available
struct sip_msg {
    // Define the structure members as per the actual definition
    char *buf; // Example member
    int len;   // Example member
};

// Function prototype for the function-under-test
int parse_via_header(struct sip_msg *msg, int len, struct via_body **via);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    if (size < sizeof(struct sip_msg)) {
        return 0; // Not enough data to form a valid sip_msg
    }

    // Allocate and initialize a sip_msg structure
    struct sip_msg msg;
    msg.buf = (char *)data; // Use the input data as the buffer
    msg.len = (int)size;    // Set the length to the size of the input data

    // Allocate a via_body pointer
    struct via_body *via = NULL;

    // Call the function-under-test
    int result = parse_via_header(&msg, msg.len, &via);

    // Clean up if necessary
    // If parse_via_header allocates memory for via, ensure to free it if needed
    if (via != NULL) {
        free(via);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif