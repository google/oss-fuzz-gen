#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "roaring/roaring64.h" // Correct header file for the roaring64_bitmap_t type

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0; // Ensure there's enough data for two 64-bit integers
    }

    // Initialize two roaring64_bitmap_t structures
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Use the first 8 bytes to add a value to bitmap1
    uint64_t value1 = *((uint64_t*)data);
    roaring64_bitmap_add(bitmap1, value1);

    // Use the next 8 bytes to add a value to bitmap2
    uint64_t value2 = *((uint64_t*)(data + 8));
    roaring64_bitmap_add(bitmap2, value2);

    // Add more values to increase the chance of invoking different code paths
    for (size_t i = 16; i + 8 <= size; i += 8) {
        uint64_t additional_value = *((uint64_t*)(data + i));
        if (i % 2 == 0) {
            roaring64_bitmap_add(bitmap1, additional_value);
        } else {
            roaring64_bitmap_add(bitmap2, additional_value);
        }
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_is_strict_subset(bitmap1, bitmap2);

    // Perform additional operations to increase coverage
    roaring64_bitmap_and_inplace(bitmap1, bitmap2);
    roaring64_bitmap_or_inplace(bitmap1, bitmap2);

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
