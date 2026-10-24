#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in a header file or elsewhere
// int nc_get_att_schar(int, int, const char *, signed char *);

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the data
    int param1 = (int)data[0];
    int param2 = (int)data[1];

    // Create a null-terminated string for the third parameter
    size_t str_len = size - 2;
    char *param3 = (char *)malloc(str_len + 1);
    if (param3 == NULL) {
        return 0;
    }
    memcpy(param3, data + 2, str_len);
    param3[str_len] = '\0';

    // Allocate memory for the fourth parameter
    signed char result;
    signed char *param4 = &result;

    // Call the function-under-test
    nc_get_att_schar(param1, param2, param3, param4);

    // Clean up
    free(param3);

    return 0;
}