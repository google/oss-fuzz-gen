// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_lazy_xor_inplace at roaring.c:2578:6 in roaring.h
// roaring_bitmap_equals at roaring.c:1943:6 in roaring.h
// roaring_bitmap_jaccard_index at roaring.c:2889:8 in roaring.h
// roaring_bitmap_and_inplace at roaring.c:812:6 in roaring.h
// roaring_bitmap_lazy_or at roaring.c:2324:19 in roaring.h
// roaring_bitmap_repair_after_lazy at roaring.c:2660:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_andnot at roaring.c:1194:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);
    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_lazy_xor_inplace
    roaring_bitmap_lazy_xor_inplace(bitmap1, bitmap2);

    // Test roaring_bitmap_equals
    bool equals = roaring_bitmap_equals(bitmap1, bitmap2);

    // Test roaring_bitmap_jaccard_index
    double jaccard_index = roaring_bitmap_jaccard_index(bitmap1, bitmap2);

    // Test roaring_bitmap_and_inplace
    roaring_bitmap_and_inplace(bitmap1, bitmap2);

    // Test roaring_bitmap_lazy_or
    roaring_bitmap_t *lazy_or_result = roaring_bitmap_lazy_or(bitmap1, bitmap2, true);
    if (lazy_or_result) {
        roaring_bitmap_repair_after_lazy(lazy_or_result);
        roaring_bitmap_free(lazy_or_result);
    }

    // Test roaring_bitmap_andnot
    roaring_bitmap_t *andnot_result = roaring_bitmap_andnot(bitmap1, bitmap2);
    if (andnot_result) {
        roaring_bitmap_free(andnot_result);
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

        LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    