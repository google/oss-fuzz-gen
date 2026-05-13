#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming nc__create is defined somewhere else
int nc__create(const char *name, int flags, size_t size, size_t *created_size, int *error_code);

int LLVMFuzzerTestOneInput_466(const uint8_t *data, size_t size) {
    // Ensure we have enough data to create meaningful inputs
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Calculate the maximum length for the name to avoid overflow
    size_t max_name_len = size - sizeof(int) - sizeof(size_t);
    size_t name_len = max_name_len < 255 ? max_name_len : 255;

    // Allocate memory for the name and ensure it's null-terminated
    char name[256];
    memcpy(name, data, name_len);
    name[name_len] = '\0';

    // Extract integer and size_t values from the data
    int flags = *((int *)(data + name_len));
    size_t input_size = *((size_t *)(data + name_len + sizeof(int)));

    // Initialize the output parameters
    size_t created_size = 0;
    int error_code = 0;

    // Call the function under test
    nc__create(name, flags, input_size, &created_size, &error_code);

    return 0;
}