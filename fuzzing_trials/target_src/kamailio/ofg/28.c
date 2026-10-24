#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of str is something like this
typedef struct {
    char *data;
    size_t length;
} str;

// Function-under-test
int normalize_tel_user(char *tel, str *output);

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a non-null tel string
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the tel string
    char *tel = (char *)malloc(size + 1);
    if (tel == NULL) {
        return 0;
    }

    // Copy data into tel and null-terminate it
    memcpy(tel, data, size);
    tel[size] = '\0';

    // Initialize the str structure
    str output;
    output.data = (char *)malloc(size + 1); // Allocate memory for output data
    if (output.data == NULL) {
        free(tel);
        return 0;
    }
    output.length = size;

    // Call the function-under-test
    normalize_tel_user(tel, &output);

    // Clean up
    free(tel);
    free(output.data);

    return 0;
}

#ifdef __cplusplus
}
#endif