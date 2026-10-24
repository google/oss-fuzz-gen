// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_rank at roaring.c:2677:10 in roaring.h
// roaring_bitmap_get_cardinality at roaring.c:1355:10 in roaring.h
// roaring_bitmap_range_cardinality_closed at roaring.c:1374:10 in roaring.h
// roaring_bitmap_range_cardinality at roaring.c:1364:10 in roaring.h
// roaring_bitmap_rank_many at roaring.c:2696:6 in roaring.h
// roaring_bitmap_range_uint32_array at roaring.c:1433:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
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

int LLVMFuzzerTestOneInput_101(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    roaring_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) return 0;

    uint32_t x;
    memcpy(&x, Data, sizeof(uint32_t));

    // Test roaring_bitmap_rank
    uint64_t rank = roaring_bitmap_rank(bitmap, x);

    // Test roaring_bitmap_get_cardinality
    uint64_t cardinality = roaring_bitmap_get_cardinality(bitmap);

    // Test roaring_bitmap_range_cardinality_closed
    uint32_t range_start, range_end;
    range_start = x;
    range_end = x + 100; // Arbitrary range
    uint64_t cardinality_closed = roaring_bitmap_range_cardinality_closed(bitmap, range_start, range_end);

    // Test roaring_bitmap_range_cardinality
    uint64_t cardinality_range = roaring_bitmap_range_cardinality(bitmap, range_start, range_end);

    // Test roaring_bitmap_rank_many
    size_t num_elements = Size / sizeof(uint32_t);
    uint32_t *elements = (uint32_t *)malloc(num_elements * sizeof(uint32_t));
    uint64_t *ans = (uint64_t *)malloc(num_elements * sizeof(uint64_t));
    if (elements && ans) {
        memcpy(elements, Data, num_elements * sizeof(uint32_t));
        roaring_bitmap_rank_many(bitmap, elements, elements + num_elements, ans);
    }
    free(elements);
    free(ans);

    // Test roaring_bitmap_range_uint32_array
    size_t offset = 0;
    size_t limit = 10; // Arbitrary limit
    uint32_t *array_ans = (uint32_t *)malloc(limit * sizeof(uint32_t));
    if (array_ans) {
        roaring_bitmap_range_uint32_array(bitmap, offset, limit, array_ans);
    }
    free(array_ans);

    roaring_bitmap_free(bitmap);
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

        LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    