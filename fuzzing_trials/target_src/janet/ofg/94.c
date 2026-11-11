#include <stdint.h>
#include <stddef.h>
#include <janet.h> // Include the Janet library header

// Function signature provided for fuzzing
JanetRNG * janet_default_rng();

// Fuzzing harness
int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Call the function-under-test
    JanetRNG *rng = janet_default_rng();

    // Use the RNG to generate a random number (for demonstration purposes)
    if (rng != NULL) {
        double random_value = janet_rng_double(rng);
        (void)random_value; // Suppress unused variable warning
    }

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

    LLVMFuzzerTestOneInput_94(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
