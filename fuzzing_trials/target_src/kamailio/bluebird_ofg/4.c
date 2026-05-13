#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/msg_parser.h"
#include "/src/kamailio/src/core/str.h"

// Function-under-test
int get_src_uri(sip_msg_t *msg, int param, str *uri);

// Fuzzing harness
int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    if (size < sizeof(sip_msg_t) + sizeof(str)) {
        return 0;
    }

    // Initialize sip_msg_t
    sip_msg_t msg;
    memcpy(&msg, data, sizeof(sip_msg_t));

    // Initialize str
    str uri;
    uri.s = (char *)(data + sizeof(sip_msg_t));
    uri.len = (int)(size - sizeof(sip_msg_t));

    // Define a non-zero integer parameter
    int param = 1;

    // Call the function-under-test
    get_src_uri(&msg, param, &uri);

    return 0;
}