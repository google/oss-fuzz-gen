#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_324(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize a Janet variable from the input data
    Janet j = janet_wrap_integer((int32_t)data[0]); // Example: wrapping as an integer

    // Call the function-under-test
    int result = janet_unwrap_boolean(j);

    // Use the result to avoid compiler optimizations
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

    LLVMFuzzerTestOneInput_324(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
