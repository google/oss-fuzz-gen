#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static void fuzz_janet_rng_double(JanetRNG *rng) {
    double result = janet_rng_double(rng);
    (void)result; // Use the result in a meaningful way if needed
}

static void fuzz_janet_rng_longseed(JanetRNG *rng, const uint8_t *data, int32_t len) {
    janet_rng_longseed(rng, data, len);
}

static void fuzz_janet_rng_seed(JanetRNG *rng, uint32_t seed) {
    janet_rng_seed(rng, seed);
}

static void fuzz_janet_default_rng(void) {
    JanetRNG *default_rng = janet_default_rng();
    if (default_rng) {
        fuzz_janet_rng_double(default_rng);
        (void)janet_rng_u32(default_rng);
    }
}

static void fuzz_janet_rng_u32(JanetRNG *rng) {
    uint32_t result = janet_rng_u32(rng);
    (void)result; // Use the result in a meaningful way if needed
}

int LLVMFuzzerTestOneInput_584(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetRNG) + sizeof(uint32_t)) {
        return 0; // Not enough data
    }

    JanetRNG rng;
    uint32_t seed;
    const uint8_t *rng_data = Data;
    size_t rng_data_size = Size - sizeof(uint32_t);

    // Initialize the RNG with a long seed
    fuzz_janet_rng_longseed(&rng, rng_data, (int32_t)rng_data_size);

    // Extract a seed from the remaining data
    seed = *(const uint32_t *)(Data + rng_data_size);

    // Seed the RNG
    fuzz_janet_rng_seed(&rng, seed);

    // Test janet_rng_double
    fuzz_janet_rng_double(&rng);

    // Test janet_rng_u32
    fuzz_janet_rng_u32(&rng);

    // Test janet_default_rng
    fuzz_janet_default_rng();

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

    LLVMFuzzerTestOneInput_584(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
