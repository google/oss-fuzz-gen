#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>
#include "/src/croaring/include/roaring/roaring.h"
#include "/src/croaring/include/roaring/memory.h"

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two bitmaps
    if (size < 2) {
        return 0;
    }

    // Initialize two roaring64_bitmap_t structures
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Populate the bitmaps with some values derived from the input data
    for (size_t i = 0; i < size / 2; i++) {
        uint64_t value1 = (uint64_t)data[i];
        uint64_t value2 = (uint64_t)data[size / 2 + i];
        roaring64_bitmap_add(bitmap1, value1);
        roaring64_bitmap_add(bitmap2, value2);
    }

    // Call the function-under-test
    uint64_t result = roaring64_bitmap_xor_cardinality(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
