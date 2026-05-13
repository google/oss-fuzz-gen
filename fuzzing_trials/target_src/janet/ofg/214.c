#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Function signature for the fuzzer
int LLVMFuzzerTestOneInput_214(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < sizeof(Janet) * 2 + sizeof(int32_t) * 2) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create Janet values from the input data
    const Janet *janet_array = (const Janet *)data;
    int32_t n = (int32_t)size / sizeof(Janet);

    // Use the first part of the data for the first Janet array
    const Janet *first_array = janet_array;
    int32_t first_len = n / 2;

    // Use the second part of the data for the second Janet array
    const Janet *second_array = janet_array + first_len;
    int32_t second_len = n - first_len;

    // Call the function under test
    JanetTuple result = janet_opttuple(first_array, first_len, second_len, second_array);

    // Clean up Janet
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

    LLVMFuzzerTestOneInput_214(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
