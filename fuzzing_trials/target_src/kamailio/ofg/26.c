#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the correct header for parse_to_uri declaration
#include "/src/kamailio/src/core/parser/parse_addr_spec.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"

// Function-under-test
// Ensure the function signature matches the one in the included header
sip_uri_t *parse_to_uri(struct sip_msg *const msg);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to form a valid SIP message
    if (size < 4) { // Adjust the minimum size based on expected input
        return 0;
    }

    // Allocate memory for the SIP message
    sip_msg_t sip_msg;
    memset(&sip_msg, 0, sizeof(sip_msg_t)); // Initialize the structure to avoid undefined behavior
    sip_msg.buf = (char *)data;  // Adjusted to match the actual structure definition
    sip_msg.len = size;

    // Call the function-under-test
    sip_uri_t *result = parse_to_uri(&sip_msg);

    // If necessary, free or handle the result
    // Assuming parse_to_uri allocates memory that needs to be freed
    if (result != NULL) {
        // Free or handle the result appropriately
        // free(result); // Uncomment if necessary
    }

    return 0;
}