#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_332(const uint8_t *data, size_t size) {
    // Ensure there is at least space for one Janet element
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Calculate the number of Janet elements we can fit in the data
    int32_t num_elements = size / sizeof(Janet);

    // Allocate memory for the Janet array to avoid using the read-only input buffer
    Janet *janet_array = (Janet *)malloc(num_elements * sizeof(Janet));
    if (!janet_array) {
        return 0; // If allocation fails, exit gracefully
    }

    // Copy data into janet_array
    memcpy(janet_array, data, num_elements * sizeof(Janet));

    // Initialize the Janet environment
    janet_init();

    // Call the function-under-test
    JanetTuple result = janet_tuple_n(janet_array, num_elements);

    // Use the result in some way to avoid compiler optimizations
    // (This is just a placeholder, as the actual use would depend on the context)
    (void)result;

    // Clean up the Janet environment
    janet_deinit();

    // Free the allocated memory
    free(janet_array);

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

    LLVMFuzzerTestOneInput_332(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
