#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for malloc and free
#include "janet.h"

int LLVMFuzzerTestOneInput_536(const uint8_t *data, size_t size) {
    // Ensure that the size is a multiple of the size of Janet
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Calculate the number of Janet elements we can create from the input data
    int32_t num_elements = size / sizeof(Janet);

    // Allocate memory for the Janet array
    Janet *janet_array = (Janet *)malloc(num_elements * sizeof(Janet));
    if (!janet_array) {
        return 0;
    }

    // Initialize the Janet array with data
    for (int32_t i = 0; i < num_elements; i++) {
        janet_array[i] = janet_wrap_integer(((int32_t *)data)[i]);
    }

    // Initialize the Janet runtime
    janet_init();

    // Call the function-under-test
    JanetTuple result = janet_tuple_n(janet_array, num_elements);

    // Clean up
    free(janet_array);

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

    LLVMFuzzerTestOneInput_536(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
