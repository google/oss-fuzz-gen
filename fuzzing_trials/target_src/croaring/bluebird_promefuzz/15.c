#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    // Simplified bitmap creation for fuzzing
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create two bitmaps from input data
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data, Size);

    if (bitmap1 == NULL || bitmap2 == NULL) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_xor_cardinality
    uint64_t xor_card = roaring_bitmap_xor_cardinality(bitmap1, bitmap2);

    // Test roaring_bitmap_contains_range
    uint64_t range_start = Data[0] % 256;
    uint64_t range_end = range_start + (Data[0] % 10);
    bool contains_range = roaring_bitmap_contains_range(bitmap1, range_start, range_end);

    // Test roaring_bitmap_flip
    roaring_bitmap_t *flipped_bitmap = roaring_bitmap_flip(bitmap1, range_start, range_end);
    roaring_bitmap_free(flipped_bitmap);

    // Test roaring_bitmap_or_cardinality
    uint64_t or_card = roaring_bitmap_or_cardinality(bitmap1, bitmap2);

    // Test roaring_bitmap_is_subset
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function roaring_bitmap_is_subset with roaring_bitmap_equals
    bool is_subset = roaring_bitmap_equals(bitmap1, bitmap2);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Test roaring_bitmap_range_cardinality
    uint64_t range_card = roaring_bitmap_range_cardinality(bitmap1, range_start, range_end);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
