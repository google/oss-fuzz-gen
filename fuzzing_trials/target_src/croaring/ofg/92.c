#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    // Initialize two roaring bitmaps
    roaring_bitmap_t *bitmap1 = roaring_bitmap_create();
    roaring_bitmap_t *bitmap2 = roaring_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // If either bitmap creation fails, clean up and return
        if (bitmap1 != NULL) roaring_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Add data to the first bitmap
    for (size_t i = 0; i < size / 2; ++i) {
        roaring_bitmap_add(bitmap1, data[i]);
    }

    // Add data to the second bitmap
    for (size_t i = size / 2; i < size; ++i) {
        roaring_bitmap_add(bitmap2, data[i]);
    }

    // Call the function-under-test
    roaring_bitmap_lazy_xor_inplace(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
