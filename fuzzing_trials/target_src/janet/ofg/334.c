#include <stdint.h>
#include <stddef.h>
#include "janet.h" // Assuming janet.h is the header file where Janet is defined

int LLVMFuzzerTestOneInput_334(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0; // Not enough data to form a uint64_t
    }

    // Convert the first 8 bytes of data to a uint64_t
    uint64_t bits = 0;
    for (size_t i = 0; i < sizeof(uint64_t); i++) {
        bits |= ((uint64_t)data[i]) << (i * 8);
    }

    // Call the function-under-test
    Janet result = janet_nanbox_from_bits(bits);

    // Optionally, you can do something with 'result' here

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

    LLVMFuzzerTestOneInput_334(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
