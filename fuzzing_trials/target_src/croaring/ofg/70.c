#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create at least one element
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Create two roaring64_bitmap_t instances
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Populate the first bitmap with data
    for (size_t i = 0; i < size / sizeof(uint64_t); ++i) {
        uint64_t value;
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap1, value);
    }

    // Populate the second bitmap with data
    for (size_t i = 0; i < size / sizeof(uint64_t); ++i) {
        uint64_t value;
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap2, value);
    }

    // Call the function-under-test
    roaring64_bitmap_xor_inplace(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
