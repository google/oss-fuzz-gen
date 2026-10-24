// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_init_with_capacity at roaring.c:100:6 in roaring.h
// roaring_bitmap_minimum at roaring.c:2756:10 in roaring.h
// roaring_bitmap_of_ptr at roaring.c:195:19 in roaring.h
// roaring_bitmap_get_cardinality at roaring.c:1355:10 in roaring.h
// roaring_bitmap_to_uint32_array at roaring.c:1429:6 in roaring.h
// roaring_bitmap_clear at roaring.c:562:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_init_cleared at roaring.h:61:13 in roaring.h
// roaring_bitmap_clear at roaring.c:562:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include "roaring.h"

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0; // Not enough data to proceed
    }

    // Initialize a roaring bitmap with capacity
    roaring_bitmap_t bitmap;
    uint32_t capacity = *((const uint32_t *)Data);
    if (!roaring_bitmap_init_with_capacity(&bitmap, capacity)) {
        return 0; // Memory allocation failed
    }

    // Test roaring_bitmap_minimum on an empty bitmap
    uint32_t min_val = roaring_bitmap_minimum(&bitmap);
    assert(min_val == UINT32_MAX);

    // Create a bitmap from an array of uint32_t
    size_t n_args = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;
    roaring_bitmap_t *bitmap_from_ptr = roaring_bitmap_of_ptr(n_args, vals);
    if (bitmap_from_ptr != NULL) {
        // Convert the bitmap to a uint32_t array
        size_t cardinality = roaring_bitmap_get_cardinality(bitmap_from_ptr);
        uint32_t *array = (uint32_t *)malloc(cardinality * sizeof(uint32_t));
        if (array != NULL) {
            roaring_bitmap_to_uint32_array(bitmap_from_ptr, array);
            free(array);
        }

        // Clear the bitmap
        roaring_bitmap_clear(bitmap_from_ptr);
        roaring_bitmap_free(bitmap_from_ptr);
    }

    // Initialize a cleared bitmap
    roaring_bitmap_t cleared_bitmap;
    roaring_bitmap_init_cleared(&cleared_bitmap);

    // Clear the original bitmap
    roaring_bitmap_clear(&bitmap);

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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    