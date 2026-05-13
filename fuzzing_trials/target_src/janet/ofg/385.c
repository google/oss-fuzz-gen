#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the string.h library for memcpy
#include <janet.h> // Include the Janet library header

int LLVMFuzzerTestOneInput_385(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Ensure there is enough data to create a Janet object
    if (size < sizeof(int64_t)) {
        janet_deinit(); // Clean up Janet environment before returning
        return 0;
    }

    // Create a Janet object from the input data
    int64_t value;
    memcpy(&value, data, sizeof(int64_t));
    Janet janet_value = janet_wrap_integer(value);

    // Call the function-under-test
    int result = janet_checkint64(janet_value);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_385(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
