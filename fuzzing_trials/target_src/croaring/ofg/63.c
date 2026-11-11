#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract two uint32_t values
    if (size < 2 * sizeof(uint32_t)) {
        return 0;
    }

    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Populate the bitmap with some values
    for (uint32_t i = 0; i < size / sizeof(uint32_t); i++) {
        roaring_bitmap_add(bitmap, i);
    }

    // Extract two uint32_t values from the input data
    uint32_t start = ((uint32_t *)data)[0];
    uint32_t end = ((uint32_t *)data)[1];

    // Call the function-under-test
    roaring_bitmap_t *flipped_bitmap = roaring_bitmap_flip_closed(bitmap, start, end);

    // Clean up
    if (flipped_bitmap != NULL) {
        roaring_bitmap_free(flipped_bitmap);
    }
    roaring_bitmap_free(bitmap);

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
