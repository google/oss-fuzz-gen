// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_or_inplace at roaring64.c:1447:6 in roaring64.h
// roaring64_bitmap_is_strict_subset at roaring64.c:1169:6 in roaring64.h
// roaring64_bitmap_andnot_inplace at roaring64.c:1714:6 in roaring64.h
// roaring64_bitmap_and at roaring64.c:1176:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_and_inplace at roaring64.c:1253:6 in roaring64.h
// roaring64_bitmap_xor_inplace at roaring64.c:1574:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_45(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint64_t)) {
        return 0;
    }

    roaring64_bitmap_t *r1 = create_random_bitmap(Data, Size / 2);
    roaring64_bitmap_t *r2 = create_random_bitmap(Data + Size / 2, Size / 2);

    if (!r1 || !r2) {
        roaring64_bitmap_free(r1);
        roaring64_bitmap_free(r2);
        return 0;
    }

    // Test roaring64_bitmap_or_inplace
    roaring64_bitmap_or_inplace(r1, r2);

    // Test roaring64_bitmap_is_strict_subset
    bool is_subset = roaring64_bitmap_is_strict_subset(r1, r2);

    // Test roaring64_bitmap_andnot_inplace
    roaring64_bitmap_andnot_inplace(r1, r2);

    // Test roaring64_bitmap_and
    roaring64_bitmap_t *and_result = roaring64_bitmap_and(r1, r2);
    roaring64_bitmap_free(and_result);

    // Test roaring64_bitmap_and_inplace
    roaring64_bitmap_and_inplace(r1, r2);

    // Test roaring64_bitmap_xor_inplace
    roaring64_bitmap_xor_inplace(r1, r2);

    // Cleanup
    roaring64_bitmap_free(r1);
    roaring64_bitmap_free(r2);

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

        LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    