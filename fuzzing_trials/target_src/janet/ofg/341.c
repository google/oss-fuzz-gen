#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_341(const uint8_t *data, size_t size) {
    // Initialize the Janet VM
    janet_init();

    // Check if the size is sufficient to create a Janet array
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet array from the input data
    Janet *janet_array = (Janet *)data;

    // Define index and count for testing
    int32_t index = 0;
    int32_t count = size / sizeof(Janet);

    // Define a default string
    const char *default_str = "default";

    // Call the function under test
    const char *result = janet_optcstring(janet_array, index, count, default_str);

    // Use the result to avoid compiler optimizations
    if (result) {
        // Do something with the result (e.g., print it)
    }

    // Deinitialize the Janet VM
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

    LLVMFuzzerTestOneInput_341(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
