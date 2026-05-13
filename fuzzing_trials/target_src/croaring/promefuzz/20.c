// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_is_strict_subset at roaring.c:2983:6 in roaring.h
// roaring_bitmap_equals at roaring.c:1943:6 in roaring.h
// roaring_bitmap_contains at roaring.h:467:13 in roaring.h
// roaring_bitmap_intersect_with_range at roaring.c:2840:6 in roaring.h
// roaring_bitmap_is_subset at roaring.c:1966:6 in roaring.h
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

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size / sizeof(uint32_t); i++) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2) return 0;

    // Create two random bitmaps for testing
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_is_strict_subset
    bool is_strict_subset = roaring_bitmap_is_strict_subset(bitmap1, bitmap2);

    // Test roaring_bitmap_equals
    bool equals = roaring_bitmap_equals(bitmap1, bitmap2);

    // Test roaring_bitmap_contains
    uint32_t test_value;
    memcpy(&test_value, Data, sizeof(uint32_t));
    bool contains = roaring_bitmap_contains(bitmap1, test_value);

    // Test roaring_bitmap_intersect_with_range
    uint64_t x, y;
    memcpy(&x, Data + sizeof(uint32_t), sizeof(uint64_t));
    memcpy(&y, Data + sizeof(uint32_t) + sizeof(uint64_t), sizeof(uint64_t));
    bool intersects_with_range = roaring_bitmap_intersect_with_range(bitmap1, x, y);

    // Test roaring_bitmap_is_subset
    bool is_subset = roaring_bitmap_is_subset(bitmap1, bitmap2);

    // Test roaring_bitmap_intersect
    bool intersects = roaring_bitmap_intersect(bitmap1, bitmap2);

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

        LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    