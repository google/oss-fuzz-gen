#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/str.h"

// Function-under-test
int get_src_address_socket(sip_msg_t *msg, str *address);

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize sip_msg_t
    sip_msg_t msg;
    memset(&msg, 0, sizeof(sip_msg_t)); // Zero out the structure to ensure all fields are initialized

    // Initialize any necessary fields of msg if required by the function-under-test
    if (size > 0) {
        msg.buf = (char *)malloc(size + 1);
        if (msg.buf == NULL) {
            return 0; // Exit if memory allocation fails
        }
        memcpy(msg.buf, data, size);
        msg.buf[size] = '\0'; // Null-terminate the buffer

        // Set the buffer length
        msg.len = size;

        // Call the SIP message parser to fill in the rest of the msg structure
        if (parse_msg(msg.buf, size, &msg) < 0) {
            free(msg.buf);
            return 0; // Exit if parsing fails
        }
    }

    // Initialize str
    str address;
    address.s = (char *)malloc(size + 1); // Allocate memory for address
    if (address.s == NULL) {
        if (msg.buf) free(msg.buf); // Clean up if allocation fails
        return 0;
    }
    memcpy(address.s, data, size);
    address.s[size] = '\0'; // Null-terminate the string
    address.len = size;

    // Call the function-under-test
    int result = get_src_address_socket(&msg, &address);

    // Clean up
    free(address.s);
    if (msg.buf) free(msg.buf);

    return 0;
}