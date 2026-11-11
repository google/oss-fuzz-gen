#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Function signature for the fuzzer
int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int32_t) * 2 + 1) {
        return 0;
    }

    // Initialize Janet VM
    janet_init();

    // Prepare the parameters for janet_optstring
    const Janet *janet_array = (const Janet *)data;
    int32_t n = *((int32_t *)(data + size - sizeof(int32_t) * 2));
    int32_t def = *((int32_t *)(data + size - sizeof(int32_t)));
    const uint8_t *def_str = data + size - 1; // Use the last byte as a string

    // Ensure the index 'n' is within bounds
    if (n < 0 || n >= size / sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Ensure def_str is null-terminated
    uint8_t def_str_buffer[2] = { *def_str, '\0' };

    // Call the function-under-test
    JanetString result = janet_optstring(janet_array, n, def, def_str_buffer);

    // Clean up Janet VM
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

    LLVMFuzzerTestOneInput_194(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
