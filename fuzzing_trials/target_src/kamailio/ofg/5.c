#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include necessary headers for SIP message structures
#include "/src/kamailio/src/core/parser/parse_uri.h" // Assuming this header contains the definition of struct sip_msg

// Function prototype for the function-under-test
int parse_orig_ruri(struct sip_msg *msg);

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Allocate memory for sip_msg structure
    struct sip_msg *msg = (struct sip_msg *)malloc(sizeof(struct sip_msg));
    if (msg == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the sip_msg structure
    memset(msg, 0, sizeof(struct sip_msg));

    // Assume the data is a SIP message and copy it to msg->buf
    msg->buf = (char *)malloc(size + 1);
    if (msg->buf == NULL) {
        free(msg);
        return 0; // Exit if memory allocation fails
    }
    memcpy(msg->buf, data, size);
    msg->buf[size] = '\0'; // Null-terminate the buffer

    // Set the length of the buffer
    msg->len = size;

    // Call the function-under-test
    parse_orig_ruri(msg);

    // Clean up
    free(msg->buf);
    free(msg);

    return 0;
}