#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h> // Include this for size_t
#include "roaring/roaring64.h" // Correct header for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t objects
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure the bitmaps are non-NULL
    if (!bitmap1 || !bitmap2) {
        if (bitmap1) roaring64_bitmap_free(bitmap1);
        if (bitmap2) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Populate the bitmaps with some data from the input
    // Using the first half of the data for bitmap1 and the second half for bitmap2
    size_t half_size = size / 2;
    for (size_t i = 0; i < half_size; i++) {
        roaring64_bitmap_add(bitmap1, (uint64_t)data[i]);
    }
    for (size_t i = half_size; i < size; i++) {
        roaring64_bitmap_add(bitmap2, (uint64_t)data[i]);
    }

    // Call the function-under-test
    uint64_t cardinality = roaring64_bitmap_andnot_cardinality(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
