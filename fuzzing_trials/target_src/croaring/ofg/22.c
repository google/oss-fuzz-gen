#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) * 2) {
        return 0; // Ensure there's enough data for at least two bitmaps
    }

    // Determine the number of bitmaps to create
    size_t num_bitmaps = size / sizeof(uint32_t);
    if (num_bitmaps < 2) {
        return 0; // Ensure at least two bitmaps
    }

    // Allocate memory for the array of bitmap pointers
    const roaring_bitmap_t **bitmaps = (const roaring_bitmap_t **)malloc(num_bitmaps * sizeof(roaring_bitmap_t *));
    if (bitmaps == NULL) {
        return 0; // Memory allocation failed
    }

    // Initialize bitmaps with data
    for (size_t i = 0; i < num_bitmaps; i++) {
        // Create a new bitmap
        roaring_bitmap_t *bitmap = roaring_bitmap_create();
        if (bitmap == NULL) {
            // Clean up and return if creation failed
            for (size_t j = 0; j < i; j++) {
                roaring_bitmap_free((roaring_bitmap_t *)bitmaps[j]);
            }
            free(bitmaps);
            return 0;
        }

        // Add an element to the bitmap using the data
        uint32_t value = *((const uint32_t *)(data + i * sizeof(uint32_t)));
        roaring_bitmap_add(bitmap, value);

        // Store the bitmap in the array
        bitmaps[i] = bitmap;
    }

    // Call the function-under-test
    roaring_bitmap_t *result_bitmap = roaring_bitmap_or_many(num_bitmaps, bitmaps);

    // Clean up
    for (size_t i = 0; i < num_bitmaps; i++) {
        roaring_bitmap_free((roaring_bitmap_t *)bitmaps[i]);
    }
    free(bitmaps);

    // Free the result bitmap
    if (result_bitmap != NULL) {
        roaring_bitmap_free(result_bitmap);
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
