#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_495(const uint8_t *data, size_t size) {
    // Ensure that the input size is non-zero to avoid undefined behavior
    if (size == 0) {
        return 0;
    }

    // Initialize the Janet runtime
    janet_init();

    // Create a Janet object with the input data
    Janet janet_obj = janet_stringv(data, size);

    // Call the function-under-test
    int32_t hash_value = janet_hash(janet_obj);

    // Use the hash_value to prevent compiler optimizations from removing the call
    if (hash_value == 0) {
        // Clean up the Janet runtime before returning
        janet_deinit();
        return 0;
    }

    // Clean up the Janet runtime
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

    LLVMFuzzerTestOneInput_495(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
