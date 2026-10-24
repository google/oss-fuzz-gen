#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Initialize two roaring bitmaps
    roaring_bitmap_t *bitmap1 = roaring_bitmap_create();
    roaring_bitmap_t *bitmap2 = roaring_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        return 0; // If memory allocation fails, exit early
    }

    // Populate the first bitmap with some values from the input data
    for (size_t i = 0; i < size; i += 2) {
        uint32_t value = (data[i] << 8) | data[i + 1];
        roaring_bitmap_add(bitmap1, value);
    }

    // Populate the second bitmap with some other values from the input data
    for (size_t i = 1; i < size; i += 2) {
        uint32_t value = (data[i] << 8) | data[i - 1];
        roaring_bitmap_add(bitmap2, value);
    }

    // Use a boolean flag for the lazy_or_inplace operation
    bool bit = size % 2 == 0;

    // Call the function-under-test
    roaring_bitmap_lazy_or_inplace(bitmap1, bitmap2, bit);

    // Cleanup
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
