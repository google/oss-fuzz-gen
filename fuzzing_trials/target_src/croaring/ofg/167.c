#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t)) {
        return 0; // Not enough data to determine the number of bitmaps
    }

    size_t num_bitmaps = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    if (num_bitmaps == 0 || size < num_bitmaps * sizeof(roaring_bitmap_t *)) {
        return 0; // Not enough data to create the required number of bitmaps
    }

    const roaring_bitmap_t **bitmaps = (const roaring_bitmap_t **)malloc(num_bitmaps * sizeof(roaring_bitmap_t *));
    if (bitmaps == NULL) {
        return 0; // Memory allocation failed
    }

    for (size_t i = 0; i < num_bitmaps; i++) {
        if (size < sizeof(uint32_t)) {
            free(bitmaps);
            return 0; // Not enough data to create a bitmap
        }

        uint32_t bitmap_size = *((uint32_t *)data);
        data += sizeof(uint32_t);
        size -= sizeof(uint32_t);

        if (size < bitmap_size) {
            free(bitmaps);
            return 0; // Not enough data for the bitmap
        }

        roaring_bitmap_t *bitmap = roaring_bitmap_create();
        if (bitmap == NULL) {
            free(bitmaps);
            return 0; // Bitmap creation failed
        }

        for (uint32_t j = 0; j < bitmap_size; j++) {
            if (size < sizeof(uint32_t)) {
                roaring_bitmap_free(bitmap);
                free(bitmaps);
                return 0; // Not enough data to add to the bitmap
            }

            uint32_t value = *((uint32_t *)data);
            data += sizeof(uint32_t);
            size -= sizeof(uint32_t);

            roaring_bitmap_add(bitmap, value);
        }

        bitmaps[i] = bitmap;
    }

    roaring_bitmap_t *result = roaring_bitmap_xor_many(num_bitmaps, bitmaps);

    if (result != NULL) {
        roaring_bitmap_free(result);
    }

    for (size_t i = 0; i < num_bitmaps; i++) {
        roaring_bitmap_free((roaring_bitmap_t *)bitmaps[i]);
    }
    free(bitmaps);

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

    LLVMFuzzerTestOneInput_167(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
