#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_via.h"

// Assume these structures are defined in the relevant headers
struct sip_msg {
    char *buf;
    int len;
};

// Forward declaration of the function-under-test
int parse_via_header(struct sip_msg *msg, int len, struct via_body **via);

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to avoid empty input
    if (size == 0) {
        return 0;
    }

    // Allocate and initialize a sip_msg structure
    struct sip_msg msg;
    msg.buf = (char *)malloc(size + 1);
    if (msg.buf == NULL) {
        return 0;
    }
    memcpy(msg.buf, data, size);
    msg.buf[size] = '\0'; // Null-terminate to ensure it's a valid string
    msg.len = size;

    // Initialize a via_body pointer
    struct via_body *via = NULL;

    // Call the function-under-test
    int result = parse_via_header(&msg, msg.len, &via);

    // Clean up
    free(msg.buf);
    if (via != NULL) {
        // Assume there's a function to free via_body if needed
        // free_via_body(via);
    }

    return 0;
}

// Remove the dummy main function to avoid multiple definition error
// The actual fuzzing entry point is LLVMFuzzerTestOneInput.