#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Ensure that you have the Janet library available and properly linked

int LLVMFuzzerTestOneInput_248(const uint8_t *data, size_t size) {
    // Initialize Janet if not already initialized
    janet_init();

    // Allocate memory for Janet values
    Janet *janet_values = (Janet *)malloc(size * sizeof(Janet));
    if (janet_values == NULL) {
        janet_deinit();
        return 0;
    }

    // Initialize the Janet values with some data from the fuzzer input
    for (size_t i = 0; i < size; i++) {
        janet_values[i] = janet_wrap_integer(data[i]);
    }

    // Call the function-under-test
    JanetTuple result = janet_tuple_end(janet_values);

    // Clean up
    free(janet_values);

    // Deinitialize Janet if needed
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

    LLVMFuzzerTestOneInput_248(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
