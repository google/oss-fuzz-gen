#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include for memcpy
#include "janet.h"  // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract a Janet object and an int32_t index
    if (size < sizeof(Janet) + sizeof(int32_t)) {
        return 0;
    }

    // Create a buffer to store a Janet object, ensuring it's properly aligned
    Janet janet_obj;
    memcpy(&janet_obj, data, sizeof(Janet));

    // Validate the Janet object before using it
    if (!janet_checktype(janet_obj, JANET_ARRAY) && !janet_checktype(janet_obj, JANET_BUFFER)) {
        return 0;
    }

    // Extract an int32_t index from the input data
    int32_t index = *(const int32_t *)(data + sizeof(Janet));

    // Ensure the index is within a reasonable range to prevent out-of-bounds access
    int32_t length = janet_length(janet_obj);
    if (index < 0 || index >= length) {
        return 0;
    }

    // Call the function-under-test
    double result = janet_getnumber(&janet_obj, index);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_63(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
