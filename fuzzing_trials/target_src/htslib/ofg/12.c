#include <stdint.h>
#include <stddef.h> // Include this header to define 'size_t'

// Function-under-test
unsigned int hts_features(const uint8_t *data, size_t size);

// Fuzzing harness
int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (data == NULL || size == 0) {
        return 0; // Return early if input is null or size is zero
    }

    // Directly call the function-under-test with the fuzzing input
    unsigned int features = hts_features(data, size);

    // Use the result in some way to avoid compiler optimizations
    // that might remove the call if the result is unused
    if (features == 0) {
        // Do nothing, just a dummy check
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

    LLVMFuzzerTestOneInput_12(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
