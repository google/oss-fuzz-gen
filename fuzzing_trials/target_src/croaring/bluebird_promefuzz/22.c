#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_22(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    if (!bitmap1) return 0;

    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data, Size);
    if (!bitmap2) {
        roaring_bitmap_free(bitmap1);
        return 0;
    }

    // Test roaring_bitmap_to_bitset
    bitset_t *bitset = bitset_create();
    if (bitset) {
        roaring_bitmap_to_bitset(bitmap1, bitset);
        bitset_free(bitset);
    }

    // Test roaring_bitmap_run_optimize
    roaring_bitmap_run_optimize(bitmap1);

    // Test roaring_bitmap_statistics
    roaring_statistics_t stats;
    roaring_bitmap_statistics(bitmap1, &stats);

    // Test roaring_bitmap_lazy_or
    roaring_bitmap_t *lazy_or_result = roaring_bitmap_lazy_or(bitmap1, bitmap2, true);
    if (lazy_or_result) {
        roaring_bitmap_repair_after_lazy(lazy_or_result);
        roaring_bitmap_free(lazy_or_result);
    }

    // Test roaring_contains_shared
    roaring_contains_shared(bitmap1);

    // Test roaring_bitmap_is_empty
    roaring_bitmap_is_empty(bitmap1);

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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
