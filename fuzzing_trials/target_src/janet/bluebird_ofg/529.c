#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "janet.h"

// Ensure that we link against the Janet library during the build process
// This may require additional build configuration outside of this code

int LLVMFuzzerTestOneInput_529(const uint8_t *data, size_t size) {
    // Ensure the input data is null-terminated to be used as a C string
    if (size == 0) {
        return 0; // No data to process
    }

    // Allocate memory for the C string and ensure null termination
    char *cstring = (char *)malloc(size + 1);
    if (cstring == NULL) {
        return 0; // Memory allocation failed, exit gracefully
    }
    
    memcpy(cstring, data, size);
    cstring[size] = '\0'; // Null-terminate the string

    // Initialize the Janet runtime before calling any Janet functions
    janet_init();

    // Call the function-under-test
    JanetString result = janet_cstring(cstring);

    // Check if the result is not NULL and handle it appropriately
    if (result != NULL) {
        // Perform some operation with the result to ensure it's used
        size_t result_length = janet_string_length(result);
        // Use the result length in some meaningful way
        if (result_length > 0) {
            // For example, print the first character (if any) to ensure the result is used
            uint8_t first_char = janet_string_head(result);
            (void)first_char; // Suppress unused variable warning
        }
    }

    // Clean up
    free(cstring);

    // Deinitialize the Janet runtime
    janet_deinit();

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_529(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
