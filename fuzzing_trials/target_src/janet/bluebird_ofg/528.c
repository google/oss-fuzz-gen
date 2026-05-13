#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_528(const uint8_t *data, size_t size) {
    // Ensure there is enough data to use
    if (size < 2) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a Janet struct
    JanetKV *kv = janet_struct_begin(2);
    kv[0].key = janet_wrap_integer(1);  // Example key
    kv[0].value = janet_wrap_integer(2);  // Example value
    JanetStruct janet_struct = janet_struct_end(kv);

    // Create a Janet value from the input data
    Janet janet_value = janet_wrap_integer((int32_t)data[0]);

    // Ensure the key exists in the struct to avoid undefined behavior
    if (!janet_equals(janet_value, kv[0].key) && !janet_equals(janet_value, kv[0].value)) {
        janet_value = kv[0].key; // Default to a known key
    }

    // Call the function-under-test
    Janet result = janet_struct_get(janet_struct, janet_value);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_528(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
