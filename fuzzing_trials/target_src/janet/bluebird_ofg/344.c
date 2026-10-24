#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Function prototype for janet_struct_find
const JanetKV *janet_struct_find(JanetStruct st, Janet key);

int LLVMFuzzerTestOneInput_344(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a dummy JanetKV array with some default values
    JanetKV kv_array[2];
    kv_array[0].key = janet_wrap_integer(1);
    kv_array[0].value = janet_wrap_string(janet_cstring("value1"));
    kv_array[1].key = janet_wrap_integer(2);
    kv_array[1].value = janet_wrap_string(janet_cstring("value2"));

    // Create a Janet structure from the kv_array
    JanetStruct janet_struct = janet_struct_begin(2);
    janet_struct_put(janet_struct, kv_array[0].key, kv_array[0].value);
    janet_struct_put(janet_struct, kv_array[1].key, kv_array[1].value);
    janet_struct_end(janet_struct);

    // Ensure the size is sufficient to create a Janet integer
    if (size < sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    // Use the first 4 bytes of data to create a Janet integer
    int32_t key_value = *(int32_t *)data;
    Janet key = janet_wrap_integer(key_value);

    // Call the function-under-test
    const JanetKV *result = janet_struct_find(janet_struct, key);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_344(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
