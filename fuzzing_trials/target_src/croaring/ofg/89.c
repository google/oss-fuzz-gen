#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring.h" // Include the header for the roaring bitmap library

int LLVMFuzzerTestOneInput_89(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract two uint64_t values
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Initialize the roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Populate the bitmap with some values for testing
    for (uint32_t i = 0; i < 100; i++) {
        roaring_bitmap_add(bitmap, i);
    }

    // Extract two uint64_t values from the input data
    uint64_t range_start = *((const uint64_t *)data);
    uint64_t range_end = *((const uint64_t *)(data + sizeof(uint64_t)));

    // Ensure range_end is greater than or equal to range_start
    if (range_end < range_start) {
        range_end = range_start;
    }

    // Call the function-under-test
    bool result = roaring_bitmap_intersect_with_range(bitmap, range_start, range_end);

    // Clean up
    roaring_bitmap_free(bitmap);

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

    LLVMFuzzerTestOneInput_89(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
