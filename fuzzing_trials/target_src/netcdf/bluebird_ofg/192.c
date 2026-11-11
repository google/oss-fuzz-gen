#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assume this is the function-under-test from the library
int nc_put_var_string(int ncid, int varid, const char **op);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_192(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 4) return 0;

    // Extract ncid and varid from the first bytes
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // The rest of the data will be used to construct strings
    size_t num_strings = (size - 2) / 2; // Arbitrary number of strings
    if (num_strings == 0) return 0;

    // Allocate memory for string pointers
    const char **strings = (const char **)malloc(num_strings * sizeof(char *));
    if (strings == NULL) return 0;

    // Fill the strings array with non-NULL strings
    for (size_t i = 0; i < num_strings; ++i) {
        size_t str_length = (size - 2) / num_strings;
        char *str = (char *)malloc(str_length + 1);
        if (str == NULL) {
            // Free previously allocated strings
            for (size_t j = 0; j < i; ++j) {
                free((void *)strings[j]);
            }
            free(strings);
            return 0;
        }
        memcpy(str, &data[2 + i * str_length], str_length);
        str[str_length] = '\0'; // Null-terminate the string
        strings[i] = str;
    }

    // Call the function-under-test
    nc_put_var_string(ncid, varid, strings);

    // Free allocated memory
    for (size_t i = 0; i < num_strings; ++i) {
        free((void *)strings[i]);
    }
    free(strings);

    return 0;
}