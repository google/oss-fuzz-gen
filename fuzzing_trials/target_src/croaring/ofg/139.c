#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h" // Correct include for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Declare and initialize the roaring64_bitmap_t pointers
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // If either bitmap creation fails, clean up and return
        if (bitmap1 != NULL) roaring64_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Populate the bitmaps with some data from the input
    // Here we use the input data to add some values to the bitmaps
    for (size_t i = 0; i < size / 8; i++) {
        uint64_t value;
        // Ensure that we don't read out of bounds
        if (i * 8 + 8 <= size) {
            // Copy 8 bytes from data to value
            value = ((uint64_t)data[i * 8 + 0] << 0) |
                    ((uint64_t)data[i * 8 + 1] << 8) |
                    ((uint64_t)data[i * 8 + 2] << 16) |
                    ((uint64_t)data[i * 8 + 3] << 24) |
                    ((uint64_t)data[i * 8 + 4] << 32) |
                    ((uint64_t)data[i * 8 + 5] << 40) |
                    ((uint64_t)data[i * 8 + 6] << 48) |
                    ((uint64_t)data[i * 8 + 7] << 56);

            // Add the value to the bitmaps
            roaring64_bitmap_add(bitmap1, value);
            roaring64_bitmap_add(bitmap2, value + 1); // Slightly different values
        }
    }

    // Call the function under test
    roaring64_bitmap_and_inplace(bitmap1, bitmap2);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
