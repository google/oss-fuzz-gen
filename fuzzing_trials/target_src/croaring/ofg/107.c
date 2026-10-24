#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_107(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t instances
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure both bitmaps are not NULL
    if (bitmap1 == NULL || bitmap2 == NULL) {
        if (bitmap1 != NULL) roaring64_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Populate the bitmaps with data
    // For simplicity, let's use the first half of the data for bitmap1 and the second half for bitmap2
    for (size_t i = 0; i < size / 2; i++) {
        roaring64_bitmap_add(bitmap1, data[i]);
    }

    for (size_t i = size / 2; i < size; i++) {
        roaring64_bitmap_add(bitmap2, data[i]);
    }

    // Call the function-under-test
    bool is_subset = roaring64_bitmap_is_subset(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
