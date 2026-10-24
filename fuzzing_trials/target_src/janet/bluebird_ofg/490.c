#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Forward declaration of the function under test
extern Janet janet_struct_rawget(const JanetKV *st, Janet key);

int LLVMFuzzerTestOneInput_490(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) * 2) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Initialize a JanetStruct with at least one key-value pair
    JanetKV *kv = janet_struct_begin(1); // Begin a JanetStruct with 1 key-value pair
    kv[0].key = janet_wrap_integer(1); // Arbitrary non-NULL value
    kv[0].value = janet_wrap_integer(2); // Arbitrary non-NULL value

    // Finalize the JanetStruct
    const JanetKV *janetStruct = janet_struct_end(kv);

    // Use part of the data as the key
    Janet key = janet_wrap_integer((int32_t)data[0]);

    // Call the function-under-test
    Janet value = janet_struct_rawget(janetStruct, key);

    // Use the value in some way to avoid compiler optimizations
    (void)value;

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

    LLVMFuzzerTestOneInput_490(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
