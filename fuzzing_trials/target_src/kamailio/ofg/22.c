#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Include the correct header for sip_msg and str definitions
#include "/src/kamailio/src/core/parser/msg_parser.h"

// Function signature for the function-under-test
int set_ua(struct sip_msg *msg, str *user_agent);

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize and allocate memory for sip_msg
    struct sip_msg msg;
    memset(&msg, 0, sizeof(msg)); // Ensure the structure is zeroed out

    // Initialize and allocate memory for str
    str user_agent;
    user_agent.s = (char *)malloc(size + 1); // Allocate memory for the string
    if (user_agent.s == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(user_agent.s, data, size); // Copy data into the string
    user_agent.s[size] = '\0'; // Null-terminate the string
    user_agent.len = size;

    // Call the function-under-test
    set_ua(&msg, &user_agent);

    // Free allocated memory
    free(user_agent.s);

    return 0;
}