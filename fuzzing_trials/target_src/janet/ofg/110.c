#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure the janet_init function is called to initialize the Janet runtime
__attribute__((constructor))
static void initialize_janet_110() {
    janet_init();
}

extern int32_t janet_optinteger(const Janet *, int32_t, int32_t, int32_t);

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t) + 3 * sizeof(int32_t)) {
        return 0; // Not enough data to fill the parameters
    }

    // Initialize the Janet array from the input data
    Janet janet_array[1];
    // Ensure the data is interpreted as a valid Janet type
    janet_array[0] = janet_wrap_integer(*(const int32_t *)data);

    // Extract integer values from the input data
    int32_t def = *(const int32_t *)(data + sizeof(int32_t));
    int32_t lo = *(const int32_t *)(data + 2 * sizeof(int32_t));
    int32_t hi = *(const int32_t *)(data + 3 * sizeof(int32_t));

    // Call the function-under-test
    int32_t result = janet_optinteger(janet_array, 0, lo, hi);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_110(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
