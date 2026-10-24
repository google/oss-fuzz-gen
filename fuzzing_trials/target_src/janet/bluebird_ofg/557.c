#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

extern uint64_t janet_optuinteger64(const Janet *array, int32_t n, int32_t idx, uint64_t def);

int LLVMFuzzerTestOneInput_557(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract meaningful data
    if (size < sizeof(uint64_t) + sizeof(int32_t) * 2) {
        return 0;
    }

    // Initialize Janet array with at least one element
    Janet janet_array[1];
    janet_array[0] = janet_wrap_integer((int32_t)data[0]);

    // Extract parameters from data
    int32_t n = (int32_t)data[1];
    int32_t idx = (int32_t)data[2];
    uint64_t def = *((uint64_t *)(data + 3));

    // Call the function-under-test
    uint64_t result = janet_optuinteger64(janet_array, n, idx, def);

    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_557(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
