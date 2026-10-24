#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// Assuming the definition of the sip_msg structure
struct sip_msg {
    char *uri;
    size_t uri_len;
};

// Function-under-test
int parse_sip_msg_uri(struct sip_msg *msg);

int LLVMFuzzerTestOneInput_40(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the sip_msg structure
    struct sip_msg msg;
    
    // Allocate memory for the URI and ensure it is null-terminated
    msg.uri = (char *)malloc(size + 1);
    if (msg.uri == NULL) {
        return 0;
    }
    memcpy(msg.uri, data, size);
    msg.uri[size] = '\0';  // Null-terminate the URI

    // Set the URI length
    msg.uri_len = size;

    // Call the function-under-test
    parse_sip_msg_uri(&msg);

    // Free allocated memory
    free(msg.uri);

    return 0;
}

#ifdef __cplusplus
}
#endif