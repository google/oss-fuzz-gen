#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h" // Assuming this header contains the declaration for JanetRNG and janet_rng_longseed

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    JanetRNG rng;
    const uint8_t *seed_data = data;
    int32_t seed_length = (int32_t)size;

    // Ensure seed_length is not negative
    if (seed_length < 0) {
        seed_length = 0;
    }

    // Call the function-under-test
    janet_rng_longseed(&rng, seed_data, seed_length);

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

    LLVMFuzzerTestOneInput_88(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
