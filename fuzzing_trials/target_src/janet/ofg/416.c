#include <stdint.h>
#include <janet.h>

// Function prototype for the fuzzer entry point
int LLVMFuzzerTestOneInput_416(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Ensure the size is adequate to create two Janet objects
    if (size < 2 * sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create two Janet objects from the input data
    Janet first = janet_wrap_integer((int32_t)data[0]);
    Janet second = janet_wrap_integer((int32_t)data[1]);

    // Call the function-under-test
    Janet result = janet_next(first, second);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_416(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
