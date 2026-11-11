#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"  // Assuming the JanetRNG structure and function are defined in this header

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Initialize a JanetRNG structure
    JanetRNG rng;

    // Ensure the data size is sufficient for initialization
    if (size < sizeof(JanetRNG)) {
        return 0;
    }

    // Initialize the JanetRNG structure with some data
    // This is a simple example, in practice you would use the data to initialize the RNG
    memcpy(&rng, data, sizeof(JanetRNG));

    // Call the function-under-test
    double result = janet_rng_double(&rng);

    // Use the result to prevent any compiler optimizations that might remove the call
    volatile double prevent_optimization = result;
    (void)prevent_optimization;

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

    LLVMFuzzerTestOneInput_66(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
