// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_or_cardinality at roaring64.c:1439:10 in roaring64.h
// roaring64_bitmap_minimum at roaring64.c:961:10 in roaring64.h
// roaring64_bitmap_minimum at roaring64.c:961:10 in roaring64.h
// roaring64_bitmap_range_cardinality at roaring64.c:904:10 in roaring64.h
// roaring64_bitmap_andnot_cardinality at roaring64.c:1707:10 in roaring64.h
// roaring64_bitmap_get_cardinality at roaring64.c:892:10 in roaring64.h
// roaring64_bitmap_get_cardinality at roaring64.c:892:10 in roaring64.h
// roaring64_bitmap_sub_offset at roaring64.h:554:35 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i + sizeof(uint64_t) <= Size; i += sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, Data + i, sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    roaring64_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring64_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring64_bitmap_or_cardinality
    uint64_t or_cardinality = roaring64_bitmap_or_cardinality(bitmap1, bitmap2);

    // Test roaring64_bitmap_minimum
    uint64_t min1 = roaring64_bitmap_minimum(bitmap1);
    uint64_t min2 = roaring64_bitmap_minimum(bitmap2);

    // Test roaring64_bitmap_range_cardinality
    uint64_t range_cardinality = roaring64_bitmap_range_cardinality(bitmap1, min1, min1 + 10);

    // Test roaring64_bitmap_andnot_cardinality
    uint64_t andnot_cardinality = roaring64_bitmap_andnot_cardinality(bitmap1, bitmap2);

    // Test roaring64_bitmap_get_cardinality
    uint64_t cardinality1 = roaring64_bitmap_get_cardinality(bitmap1);
    uint64_t cardinality2 = roaring64_bitmap_get_cardinality(bitmap2);

    // Test roaring64_bitmap_sub_offset
    roaring64_bitmap_t *sub_bitmap = roaring64_bitmap_sub_offset(bitmap1, 5);
    if (sub_bitmap) {
        roaring64_bitmap_free(sub_bitmap);
    }

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

        LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    