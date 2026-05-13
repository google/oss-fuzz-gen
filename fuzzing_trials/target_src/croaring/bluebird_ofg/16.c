#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring/roaring64.h"  // Correct path for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Declare and initialize two roaring64_bitmap_t objects
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // Ensure memory allocation was successful
        if (bitmap1 != NULL) roaring64_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Add elements to the bitmaps using the input data
    for (size_t i = 0; i < size / 2; i++) {
        uint64_t value1 = (uint64_t)data[i];
        uint64_t value2 = (uint64_t)data[size / 2 + i];
        roaring64_bitmap_add(bitmap1, value1);
        roaring64_bitmap_add(bitmap2, value2);
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_equals(bitmap1, bitmap2);

    // Clean up the bitmaps
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
