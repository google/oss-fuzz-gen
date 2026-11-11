#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_238(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a Janet object
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Create a Janet object from the input data
    int32_t integer_value = *((int32_t *)data);
    Janet janet_value = janet_wrap_integer(integer_value);

    // Call the function-under-test using the macro
    int32_t result = janet_unwrap_integer(janet_value);

    // Use the result in some way to prevent compiler optimizations from removing the call
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

    LLVMFuzzerTestOneInput_238(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
