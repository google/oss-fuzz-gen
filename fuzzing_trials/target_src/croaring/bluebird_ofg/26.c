#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure there is enough data to proceed
    if (size < 2) {
        return 0;
    }

    // Initialize two roaring bitmaps
    roaring_bitmap_t *bitmap1 = roaring_bitmap_create();
    roaring_bitmap_t *bitmap2 = roaring_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // Clean up and return if memory allocation failed
        if (bitmap1 != NULL) roaring_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Populate the first bitmap with some values from the data
    for (size_t i = 0; i < size / 2; ++i) {
        roaring_bitmap_add(bitmap1, data[i]);
    }

    // Populate the second bitmap with some values from the data
    for (size_t i = size / 2; i < size; ++i) {
        roaring_bitmap_add(bitmap2, data[i]);
    }

    // Use the first byte of data to determine the boolean parameter
    _Bool bitsetconversion = data[0] % 2;

    // Call the function under test
    roaring_bitmap_lazy_or_inplace(bitmap1, bitmap2, bitsetconversion);

    // Clean up
    roaring_bitmap_free(bitmap1);
    roaring_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
