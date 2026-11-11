#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // Include this header for malloc and free

extern int nc_rc_set(const char *param1, const char *param2);

int LLVMFuzzerTestOneInput_430(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to split into two non-NULL strings
    if (size < 2) {
        return 0;
    }

    // Split the input data into two parts for the two string parameters
    size_t mid = size / 2;
    
    // Allocate memory for the strings and ensure they are null-terminated
    char *param1 = (char *)malloc(mid + 1);
    char *param2 = (char *)malloc(size - mid + 1);

    if (param1 == NULL || param2 == NULL) {
        free(param1);
        free(param2);
        return 0;
    }

    memcpy(param1, data, mid);
    param1[mid] = '\0';

    memcpy(param2, data + mid, size - mid);
    param2[size - mid] = '\0';

    // Call the function-under-test
    nc_rc_set(param1, param2);

    // Free allocated memory
    free(param1);
    free(param2);

    return 0;
}