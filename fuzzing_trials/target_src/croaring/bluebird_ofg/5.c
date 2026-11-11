#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0;
    }

    // Determine the number of bitmaps
    size_t num_bitmaps = data[0] % 10 + 1; // Ensure at least 1 bitmap and at most 10
    size_t bitmap_size = (size - 1) / num_bitmaps;

    // Allocate memory for the array of bitmap pointers
    const roaring_bitmap_t **bitmaps = (const roaring_bitmap_t **)malloc(num_bitmaps * sizeof(roaring_bitmap_t *));
    if (!bitmaps) {
        return 0;
    }

    // Create each bitmap from the data
    for (size_t i = 0; i < num_bitmaps; i++) {
        size_t offset = 1 + i * bitmap_size;
        size_t length = (i == num_bitmaps - 1) ? size - offset : bitmap_size;
        bitmaps[i] = roaring_bitmap_create_with_capacity(0);
        if (bitmaps[i] && length > 0) {
            // Convert data to uint32_t array
            uint32_t *values = (uint32_t *)malloc(length * sizeof(uint32_t));
            if (values) {
                memcpy(values, data + offset, length * sizeof(uint8_t));
                roaring_bitmap_add_many(bitmaps[i], length / sizeof(uint32_t), values);
                free(values);
            }
        }
    }

    // Call the function-under-test
    roaring_bitmap_t *result = roaring_bitmap_xor_many(num_bitmaps, bitmaps);

    // Free the allocated bitmaps
    for (size_t i = 0; i < num_bitmaps; i++) {
        if (bitmaps[i]) {
            roaring_bitmap_free((roaring_bitmap_t *)bitmaps[i]);
        }
    }
    free(bitmaps);

    // Free the result bitmap
    if (result) {
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
