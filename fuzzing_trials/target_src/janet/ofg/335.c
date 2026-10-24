#include <stdint.h>
#include <stddef.h>
#include "janet.h" // Assuming the Janet library provides this header

// Remove the 'extern "C"' linkage specification, as it is not valid in C
int LLVMFuzzerTestOneInput_335(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t bits;
    // Copy the first 8 bytes from data to bits
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        ((uint8_t*)&bits)[i] = data[i];
    }

    // Call the function-under-test
    Janet result = janet_nanbox_from_bits(bits);

    // Use the result in some way to prevent optimizations from removing the call
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

    LLVMFuzzerTestOneInput_335(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
