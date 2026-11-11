#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the correct header file for sip_msg_t and str
#include "/src/kamailio/src/core/parser/msg_parser.h"

extern int get_src_uri(sip_msg_t *, int, str *);

int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for fuzzing
    if (size < sizeof(sip_msg_t) + sizeof(str)) {
        return 0;
    }

    // Allocate and initialize sip_msg_t
    sip_msg_t *sip_msg = (sip_msg_t *)malloc(sizeof(sip_msg_t));
    if (sip_msg == NULL) {
        return 0;
    }
    memset(sip_msg, 0, sizeof(sip_msg_t));

    // Allocate and initialize str
    str *uri_str = (str *)malloc(sizeof(str));
    if (uri_str == NULL) {
        free(sip_msg);
        return 0;
    }
    memset(uri_str, 0, sizeof(str));

    // Initialize str with data from the fuzzing input
    uri_str->s = (char *)data;
    uri_str->len = size;

    // Use a fixed integer value for the second parameter
    int some_int = 1;

    // Call the function-under-test
    get_src_uri(sip_msg, some_int, uri_str);

    // Clean up
    free(sip_msg);
    free(uri_str);

    return 0;
}