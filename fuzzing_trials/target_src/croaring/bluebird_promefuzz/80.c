#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return NULL;
    }

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data, Size);

    if (bitmap1 && bitmap2) {
        // Test roaring_bitmap_add_range
        uint64_t min = Data[0] % UINT32_MAX;
        uint64_t max = (Data[0] + 100) % UINT32_MAX;
        if (min < max) {
            roaring_bitmap_add_range(bitmap1, min, max);
        }

        // Test roaring_bitmap_or
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function roaring_bitmap_or with roaring_bitmap_and
        roaring_bitmap_t *or_result = roaring_bitmap_and(bitmap1, bitmap2);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
        if (or_result) {
            roaring_bitmap_free(or_result);
        }

        // Test roaring_bitmap_of
        if (Size >= 3) {
            roaring_bitmap_t *bitmap_of = roaring_bitmap_of(3, Data[0], Data[1], Data[2]);
            if (bitmap_of) {
                roaring_bitmap_free(bitmap_of);
            }
        }

        // Test roaring_bitmap_or_many
        const roaring_bitmap_t *bitmaps[] = {bitmap1, bitmap2};
        roaring_bitmap_t *or_many_result = roaring_bitmap_or_many(2, bitmaps);
        if (or_many_result) {
            roaring_bitmap_free(or_many_result);
        }

        // Test roaring_bitmap_flip_inplace
        uint64_t flip_start = Data[0] % UINT32_MAX;
        uint64_t flip_end = (Data[0] + 50) % UINT32_MAX;
        if (flip_start < flip_end) {
            roaring_bitmap_flip_inplace(bitmap1, flip_start, flip_end);
        }

        // Test roaring_bitmap_range_cardinality
        uint64_t range_start = Data[0] % UINT32_MAX;
        uint64_t range_end = (Data[0] + 20) % UINT32_MAX;
        if (range_start < range_end) {
            uint64_t cardinality = roaring_bitmap_range_cardinality(bitmap1, range_start, range_end);
        }
    }

    if (bitmap1) {
        roaring_bitmap_free(bitmap1);
    }
    if (bitmap2) {
        roaring_bitmap_free(bitmap2);
    }

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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
