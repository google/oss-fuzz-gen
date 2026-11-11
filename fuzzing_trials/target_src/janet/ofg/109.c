#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int32_t janet_optinteger(const Janet *args, int32_t n, int32_t def, int32_t max);

int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + 2 * sizeof(int32_t)) {
        return 0; // Not enough data to proceed
    }

    // Initialize the Janet array
    Janet args[1];
    args[0] = janet_wrap_integer((int32_t)data[0]);

    // Extract integers from the data
    int32_t n = (int32_t)data[sizeof(Janet)];
    int32_t def = (int32_t)data[sizeof(Janet) + sizeof(int32_t)];
    int32_t max = (int32_t)data[sizeof(Janet) + 2 * sizeof(int32_t)];

    // Call the function-under-test
    int32_t result = janet_optinteger(args, n, def, max);

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

    LLVMFuzzerTestOneInput_109(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
