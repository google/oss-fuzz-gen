#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/kamailio/src/core/parser/msg_parser.h"  // Include the necessary header

// Function-under-test
char *ksr_buf_oneline(char *buf, int size);

#ifdef __cplusplus
extern "C" {
#endif

    int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
        // Ensure size is non-zero and create a buffer with a null terminator
        if (size == 0) {
            return 0;
        }

        // Allocate memory for the buffer and copy the data into it
        char *buffer = (char *)malloc(size + 1);
        if (buffer == NULL) {
            return 0;
        }
        memcpy(buffer, data, size);
        buffer[size] = '\0';  // Null-terminate the buffer

        // Call the function-under-test with various sizes to test edge cases
        for (int i = 1; i <= size; i++) {
            ksr_buf_oneline(buffer, i);
        }

        // Free the allocated buffer
        free(buffer);

        return 0;
    }

#ifdef __cplusplus
}
#endif