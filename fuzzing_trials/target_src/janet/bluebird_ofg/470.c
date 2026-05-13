#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_470(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Ensure the size is sufficient to create a JanetStruct
    if (size < 2) {
        return 0;
    }

    // Create a JanetKV array and initialize it with data
    JanetKV kv;
    kv.key = janet_wrap_integer(data[0]); // Using first byte as key
    kv.value = janet_wrap_integer(data[1]); // Using second byte as value

    // Create a JanetStruct from the JanetKV array
    JanetStruct janetStruct = janet_struct_begin(1);
    janet_struct_put(janetStruct, kv.key, kv.value);
    janet_struct_end(janetStruct);

    // Call the function-under-test
    Janet result = janet_wrap_struct(janetStruct);

    // Use the result to avoid unused variable warning
    (void)result;

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_470(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
