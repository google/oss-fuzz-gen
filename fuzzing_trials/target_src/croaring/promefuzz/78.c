// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_andnot_cardinality at roaring.c:2905:10 in roaring.h
// roaring_bitmap_xor_cardinality at roaring.c:2912:10 in roaring.h
// roaring_bitmap_and_cardinality at roaring.c:2859:10 in roaring.h
// roaring_bitmap_or_cardinality at roaring.c:2897:10 in roaring.h
// roaring_bitmap_get_cardinality at roaring.c:1355:10 in roaring.h
// roaring_bitmap_get_cardinality at roaring.c:1355:10 in roaring.h
// roaring_bitmap_range_cardinality at roaring.c:1364:10 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring.h"

static roaring_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size - Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    uint64_t card_andnot = roaring_bitmap_andnot_cardinality(bitmap1, bitmap2);
    uint64_t card_xor = roaring_bitmap_xor_cardinality(bitmap1, bitmap2);
    uint64_t card_and = roaring_bitmap_and_cardinality(bitmap1, bitmap2);
    uint64_t card_or = roaring_bitmap_or_cardinality(bitmap1, bitmap2);
    uint64_t card1 = roaring_bitmap_get_cardinality(bitmap1);
    uint64_t card2 = roaring_bitmap_get_cardinality(bitmap2);
    
    if (Size > 2) {
        uint64_t range_start = Data[0];
        uint64_t range_end = Data[1];
        if (range_start < range_end) {
            uint64_t range_card = roaring_bitmap_range_cardinality(bitmap1, range_start, range_end);
        }
    }

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

        LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    