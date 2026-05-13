#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h>

// Function to safely extract an int32_t from data
int32_t extract_int32(const uint8_t *data, size_t offset, size_t size) {
    if (offset + sizeof(int32_t) <= size) {
        return *(const int32_t *)(data + offset);
    }
    return 0; // Default value if out of bounds
}

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(uint8_t)) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize the Janet array
    const Janet *janet_array = (const Janet *)data;

    // Safely extract int32_t values from data
    int32_t index = extract_int32(data, sizeof(Janet), size);
    int32_t def = extract_int32(data, sizeof(Janet) + sizeof(int32_t), size);

    // Extract a pointer to uint8_t
    const uint8_t *key = data + sizeof(Janet) + sizeof(int32_t) * 2;

    // Ensure key is null-terminated to prevent out-of-bounds access
    if (size > sizeof(Janet) + sizeof(int32_t) * 2) {
        size_t key_length = size - (sizeof(Janet) + sizeof(int32_t) * 2);
        char *null_terminated_key = malloc(key_length + 1);
        if (!null_terminated_key) {
            return 0; // Handle allocation failure
        }
        memcpy(null_terminated_key, key, key_length);
        null_terminated_key[key_length] = '\0';

        // Ensure the Janet array has enough elements
        size_t janet_array_size = size / sizeof(Janet);
        if (index < 0 || index >= janet_array_size) {
            index = 0; // Default to a valid index
        }

        // Call the function-under-test
        JanetKeyword result = janet_optkeyword(janet_array, index, def, null_terminated_key);

        // Use the result in some way to avoid compiler optimizations
        (void)result;

        // Free allocated memory
        free(null_terminated_key);
    }

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

    LLVMFuzzerTestOneInput_265(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
