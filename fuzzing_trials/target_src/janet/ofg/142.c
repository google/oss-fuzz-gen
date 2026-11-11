#include <stdint.h>
#include <stddef.h>

// Assume JanetRNG is a defined structure
typedef struct {
    // Internal state of the RNG
    uint64_t state[4];
} JanetRNG;

// Function-under-test declaration
void janet_rng_seed(JanetRNG *rng, uint32_t seed);

// Fuzzing harness
int LLVMFuzzerTestOneInput_142(const uint8_t *data, size_t size) {
    // Initialize the RNG structure
    JanetRNG rng = {{0, 0, 0, 0}};

    // Ensure there is enough data to extract a seed
    uint32_t seed = 0;
    if (size >= sizeof(uint32_t)) {
        // Use the first 4 bytes of data as the seed
        seed = *(const uint32_t *)data;
    } else {
        // If not enough data, use a default seed
        seed = 123456789;  // Arbitrary non-zero default seed
    }

    // Call the function-under-test
    janet_rng_seed(&rng, seed);

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

    LLVMFuzzerTestOneInput_142(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
