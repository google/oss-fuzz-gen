#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include this library for memcpy

#include "/src/kamailio/src/core/parser/msg_parser.h"

// Function signature to be fuzzed
// Remove the redeclaration of msg_ctx_id_set, as it is already declared in the included header

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Ensure there is enough data to fill the structures
    if (size < sizeof(sip_msg_t) + sizeof(msg_ctx_id_t)) {
        return 0;
    }

    // Initialize sip_msg_t from the input data
    sip_msg_t *msg = (sip_msg_t *)malloc(sizeof(sip_msg_t));
    if (msg == NULL) {
        return 0;
    }
    memcpy(msg, data, sizeof(sip_msg_t));

    // Initialize msg_ctx_id_t from the input data
    msg_ctx_id_t *ctx_id = (msg_ctx_id_t *)malloc(sizeof(msg_ctx_id_t));
    if (ctx_id == NULL) {
        free(msg);
        return 0;
    }
    memcpy(ctx_id, data + sizeof(sip_msg_t), sizeof(msg_ctx_id_t));

    // Call the function under test
    int result = msg_ctx_id_set(msg, ctx_id);

    // Clean up
    free(msg);
    free(ctx_id);

    return 0;
}

#ifdef __cplusplus
}
#endif