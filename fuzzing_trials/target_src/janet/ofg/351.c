#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free
#include "janet.h" // Assuming the Janet library header is available

int LLVMFuzzerTestOneInput_351(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract required parameters
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + 1) {
        return 0;
    }

    // Extract Janet array size
    size_t janet_array_size = (size - sizeof(int32_t) * 2 - 1) / sizeof(Janet);

    // Ensure janet_array_size is not zero to avoid invalid memory operations
    if (janet_array_size == 0) {
        return 0;
    }

    Janet *janet_array = (Janet *)malloc(janet_array_size * sizeof(Janet));
    if (!janet_array) {
        return 0;
    }
    memcpy(janet_array, data, janet_array_size * sizeof(Janet));

    // Extract int32_t parameters
    int32_t arg_index = *(int32_t *)(data + janet_array_size * sizeof(Janet));
    int32_t def = *(int32_t *)(data + janet_array_size * sizeof(Janet) + sizeof(int32_t));

    // Extract string parameter
    const char *key = (const char *)(data + janet_array_size * sizeof(Janet) + sizeof(int32_t) * 2);

    // Ensure the string is null-terminated
    char key_buffer[256];
    size_t key_length = size - janet_array_size * sizeof(Janet) - sizeof(int32_t) * 2;
    if (key_length >= sizeof(key_buffer)) {
        key_length = sizeof(key_buffer) - 1;
    }
    memcpy(key_buffer, key, key_length);
    key_buffer[key_length] = '\0';

    // Validate arg_index to prevent out-of-bounds access
    if (arg_index < 0 || (size_t)arg_index >= janet_array_size) {
        free(janet_array);
        return 0;
    }

    // Call the function-under-test
    int32_t result = janet_getargindex(janet_array, arg_index, def, key_buffer);

    // Use result in some way to avoid compiler optimizations
    (void)result;

    // Free allocated memory
    free(janet_array);

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

    LLVMFuzzerTestOneInput_351(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
