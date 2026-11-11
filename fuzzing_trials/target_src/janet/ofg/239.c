#include <stdint.h>
#include <janet.h>

// Remove the incorrect extern declaration
// extern int32_t janet_unwrap_integer(Janet);

int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    if (size < sizeof(int32_t)) {
        return 0; // Not enough data to form an integer
    }

    // Initialize a Janet variable
    Janet janet_value;

    // Use the first 4 bytes of data to create an integer
    int32_t int_value = *(int32_t *)data;

    // Wrap the integer into a Janet type
    janet_value = janet_wrap_integer(int_value);

    // Call the function-under-test
    int32_t result = janet_unwrap_integer(janet_value);

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

    LLVMFuzzerTestOneInput_239(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
