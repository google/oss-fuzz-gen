#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to perform meaningful operations
    if (size < sizeof(uint32_t)) {
        return 0; // Not enough data to proceed
    }

    // Initialize the Janet environment
    janet_init();

    // Call the function-under-test
    JanetRNG *rng = janet_default_rng();

    // Perform some operations with the JanetRNG to ensure the function is exercised
    if (rng != NULL) {
        // Use the input data to seed the RNG
        uint32_t seed = *(const uint32_t *)data;
        janet_rng_seed(rng, seed);

        // Example operation: Generate a random number
        uint32_t random_number = janet_rng_u32(rng);

        // Use the random number to ensure the code is exercised
        (void)random_number;
    }

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

    LLVMFuzzerTestOneInput_93(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
