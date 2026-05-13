#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Initialize Janet environment
void initialize_janet_101() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

// Function to convert fuzz data to a Janet string object
Janet convert_to_janet_string(const uint8_t *data, size_t size) {
    // Convert the input data to a Janet string
    Janet j = janet_stringv((const char *)data, size);
    return j;
}

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    initialize_janet_101();

    // Convert the input data to a Janet string object
    Janet j = convert_to_janet_string(data, size);

    // Perform some operations on the Janet string to ensure coverage
    // For example, get the length of the string
    int32_t length = janet_string_length(janet_unwrap_string(j));

    // Use the length in some way to ensure it affects the program flow
    if (length > 0) {
        // Example operation: Print the string if it's non-empty
        janet_eprintf("Janet string: %v\n", j);
    }

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_101(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
