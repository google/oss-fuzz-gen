// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_andnot at roaring64.c:1653:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_and_cardinality at roaring64.c:1219:10 in roaring64.h
// roaring64_bitmap_intersect_with_range at roaring64.c:1363:6 in roaring64.h
// roaring64_bitmap_flip_closed at roaring64.c:1859:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_clear at roaring64.c:888:6 in roaring64.h
// roaring64_bitmap_rank at roaring64.c:663:10 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring64.h"

static roaring64_bitmap_t* create_bitmap_from_data(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i + sizeof(uint64_t) <= Size; i += sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, Data + i, sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) * 2) return 0;

    // Create two bitmaps from input data
    roaring64_bitmap_t *bitmap1 = create_bitmap_from_data(Data, Size / 2);
    roaring64_bitmap_t *bitmap2 = create_bitmap_from_data(Data + Size / 2, Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring64_bitmap_andnot
    roaring64_bitmap_t *andnot_result = roaring64_bitmap_andnot(bitmap1, bitmap2);
    if (andnot_result) roaring64_bitmap_free(andnot_result);

    // Test roaring64_bitmap_and_cardinality
    uint64_t cardinality = roaring64_bitmap_and_cardinality(bitmap1, bitmap2);

    // Test roaring64_bitmap_intersect_with_range
    uint64_t min = 0, max = UINT64_MAX;
    bool intersects = roaring64_bitmap_intersect_with_range(bitmap1, min, max);

    // Test roaring64_bitmap_flip_closed
    uint64_t flip_min = 0, flip_max = UINT64_MAX;
    roaring64_bitmap_t *flip_result = roaring64_bitmap_flip_closed(bitmap1, flip_min, flip_max);
    if (flip_result) roaring64_bitmap_free(flip_result);

    // Test roaring64_bitmap_clear
    roaring64_bitmap_clear(bitmap1);

    // Test roaring64_bitmap_rank
    uint64_t rank = roaring64_bitmap_rank(bitmap2, max);

    // Cleanup
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    