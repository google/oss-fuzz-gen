#include <stdint.h>
#include <stddef.h>
#include <janet.h>
#include <string.h> // Include this for memcpy

int LLVMFuzzerTestOneInput_405(const uint8_t *data, size_t size) {
    // Initialize the Janet runtime
    janet_init();

    // Ensure the data size is sufficient to create a valid Janet object
    if (size < sizeof(Janet)) {
        janet_deinit(); // Make sure to deinitialize before returning
        return 0;
    }

    // Cast the input data to a Janet object
    Janet janet_object;
    memcpy(&janet_object, data, sizeof(Janet));

    // Call the function-under-test
    JanetSymbol result = janet_unwrap_symbol(janet_object);

    // Use the result to prevent compiler optimizations (e.g., unused variable warnings)
    (void)result;

    // Deinitialize the Janet runtime
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

    LLVMFuzzerTestOneInput_405(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
