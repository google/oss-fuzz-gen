#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    Janet janet_value;

    // Ensure we have enough data to create a Janet value
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Create a Janet value from the input data
    janet_value = janet_wrap_integer((int32_t)data[0]);

    // Call the function under test
    janet_gcroot(janet_value);

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_98(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
