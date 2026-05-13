#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <roaring/roaring.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Initialize the roaring64_bitmap_t object
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Add some values to the bitmap
    for (size_t i = 0; i < size / sizeof(uint64_t); ++i) {
        uint64_t value_to_add = 0;
        for (size_t j = 0; j < sizeof(uint64_t); ++j) {
            value_to_add = (value_to_add << 8) | data[i * sizeof(uint64_t) + j];
        }
        roaring64_bitmap_add(bitmap, value_to_add);
    }

    // Extract a uint64_t value from the data to check for containment
    uint64_t value_to_check = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        value_to_check = (value_to_check << 8) | data[i];
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_contains(bitmap, value_to_check);

    // Clean up
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

    LLVMFuzzerTestOneInput_134(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
