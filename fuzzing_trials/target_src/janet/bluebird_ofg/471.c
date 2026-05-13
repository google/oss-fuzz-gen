#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_471(const uint8_t *data, size_t size) {
    // Initialize JanetVM
    janet_init();

    // Ensure the size is sufficient for creating a Janet
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a JanetKV array with at least one element
    JanetKV kv[1];
    kv[0].key = janet_wrap_integer(1);  // Example key
    kv[0].value = janet_wrap_integer(2); // Example value

    // Create a JanetStruct from the JanetKV array
    JanetStruct janet_struct = janet_struct_begin(1);
    janet_struct_put(janet_struct, kv[0].key, kv[0].value);
    janet_struct_end(janet_struct);

    // Use the first byte as an integer key, ensuring it's within a valid range
    Janet key = janet_wrap_integer(data[0] % 256); // Limiting the key to a valid range

    // Call the function-under-test
    Janet result = janet_struct_get(janet_struct, key);

    // Clean up JanetVM
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

    LLVMFuzzerTestOneInput_471(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
