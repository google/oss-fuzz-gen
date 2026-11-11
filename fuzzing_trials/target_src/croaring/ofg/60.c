#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Initialize two roaring64_bitmap_t objects
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Add some elements to the bitmaps based on the input data
    for (size_t i = 0; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        uint64_t value = *((const uint64_t *)(data + i));
        roaring64_bitmap_add(bitmap1, value);
        roaring64_bitmap_add(bitmap2, value + 1); // Add different values to bitmap2
    }

    // Call the function-under-test
    roaring64_bitmap_or_inplace(bitmap1, bitmap2);

    // Clean up resources
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
