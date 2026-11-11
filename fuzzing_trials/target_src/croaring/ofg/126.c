#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Initialize two roaring bitmaps
    roaring_bitmap_t *bitmap1 = roaring_bitmap_create();
    roaring_bitmap_t *bitmap2 = roaring_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // If creation failed, clean up and return
        if (bitmap1 != NULL) roaring_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Add data to the bitmaps as long as size allows
    for (size_t i = 0; i < size / 2; i++) {
        roaring_bitmap_add(bitmap1, data[i]);
    }
    for (size_t i = size / 2; i < size; i++) {
        roaring_bitmap_add(bitmap2, data[i]);
    }

    // Choose a boolean value for the lazy operation
    _Bool lazy = true;

    // Call the function under test
    roaring_bitmap_t *result = roaring_bitmap_lazy_or(bitmap1, bitmap2, lazy);

    // Clean up
    roaring_bitmap_free(bitmap1);
    roaring_bitmap_free(bitmap2);
    if (result != NULL) {
        roaring_bitmap_free(result);
    }

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

    LLVMFuzzerTestOneInput_126(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
