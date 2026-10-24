// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create_with_capacity at roaring.c:86:19 in roaring.h
// roaring_bitmap_create_with_capacity at roaring.c:86:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_add_checked at roaring.c:594:6 in roaring.h
// roaring_bitmap_add_checked at roaring.c:594:6 in roaring.h
// roaring_bitmap_equals at roaring.c:1943:6 in roaring.h
// roaring_bitmap_and_inplace at roaring.c:812:6 in roaring.h
// roaring_bitmap_contains at roaring.h:467:13 in roaring.h
// roaring_bitmap_intersect at roaring.c:2809:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring.h"

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure we have enough data

    // Initialize two roaring bitmaps with capacities derived from input data
    uint32_t cap1 = Data[0] | (Data[1] << 8);
    uint32_t cap2 = Data[2] | (Data[3] << 8);

    roaring_bitmap_t *bitmap1 = roaring_bitmap_create_with_capacity(cap1);
    roaring_bitmap_t *bitmap2 = roaring_bitmap_create_with_capacity(cap2);

    if (!bitmap1 || !bitmap2) {
        if (bitmap1) roaring_bitmap_free(bitmap1);
        if (bitmap2) roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Add values to the bitmaps
    for (size_t i = 4; i + 3 < Size; i += 4) {
        uint32_t value = Data[i] | (Data[i+1] << 8) | (Data[i+2] << 16) | (Data[i+3] << 24);
        roaring_bitmap_add_checked(bitmap1, value);
        roaring_bitmap_add_checked(bitmap2, value / 2); // Add a different value to bitmap2
    }

    // Check for equality
    roaring_bitmap_equals(bitmap1, bitmap2);

    // Perform intersection in place
    roaring_bitmap_and_inplace(bitmap1, bitmap2);

    // Check if a specific value is contained in the bitmap
    if (Size >= 8) {
        uint32_t check_value = Data[4] | (Data[5] << 8) | (Data[6] << 16) | (Data[7] << 24);
        roaring_bitmap_contains(bitmap1, check_value);
    }

    // Check if the bitmaps intersect
    roaring_bitmap_intersect(bitmap1, bitmap2);

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

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    