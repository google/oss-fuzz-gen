#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h" // Assuming the header file for JanetRNG is named janet.h

int LLVMFuzzerTestOneInput_301(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    JanetRNG rng;
    const uint8_t *seed = data;
    int32_t seed_size = (int32_t)size;

    // Ensure that the seed is not NULL and has a reasonable size
    if (seed_size <= 0) {
        return 0;
    }

    // Call the function-under-test
    janet_rng_longseed(&rng, seed, seed_size);

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

    LLVMFuzzerTestOneInput_301(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
