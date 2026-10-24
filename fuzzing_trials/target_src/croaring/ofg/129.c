#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0; // Early exit if bitmap creation fails
    }

    // Ensure we have enough data to create at least one uint64_t value
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Calculate the number of uint64_t values we can extract from the input data
    size_t num_values = size / sizeof(uint64_t);

    // Allocate memory for the uint64_t values
    uint64_t *values = (uint64_t *)malloc(num_values * sizeof(uint64_t));
    if (!values) {
        roaring64_bitmap_free(bitmap);
        return 0; // Early exit if memory allocation fails
    }

    // Populate the values array with data from the input
    for (size_t i = 0; i < num_values; ++i) {
        values[i] = ((uint64_t *)data)[i];
    }

    // Call the function-under-test
    roaring64_bitmap_remove_many(bitmap, num_values, values);

    // Clean up
    free(values);
    roaring64_bitmap_free(bitmap);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
