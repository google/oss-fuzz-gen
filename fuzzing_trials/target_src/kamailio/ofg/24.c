#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/parse_diversion.h"
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/str.h"

// Forward declaration of the function-under-test
str * get_diversion_param(struct sip_msg *, str *);

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Initialize the sip_msg structure
    struct sip_msg msg;
    memset(&msg, 0, sizeof(struct sip_msg)); // Zero out the structure to avoid garbage values
    msg.buf = (char *)data; // Casting data to char* for buffer
    msg.len = (int)size;    // Setting length of the message

    // Simulate a simple SIP message by ensuring it ends with a null terminator
    if (msg.buf[msg.len - 1] != '\0') {
        return 0; // Ensure the buffer ends with a null terminator
    }

    // Initialize the str structure
    str param;
    param.s = (char *)data; // Reusing data for the string
    param.len = (int)size;  // Setting length of the string

    // Call the function-under-test
    str *result = get_diversion_param(&msg, &param);

    // Normally, you would use the result here, but since this is a fuzzing
    // harness, we are primarily interested in discovering issues in the function call.
    // Therefore, we do not need to do anything with `result`.

    return 0;
}