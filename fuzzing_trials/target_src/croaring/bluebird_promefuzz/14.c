#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring/roaring.h"

static void fuzz_roaring_bitmap_from_range(uint64_t min, uint64_t max, uint32_t step) {
    roaring_bitmap_t *bitmap = roaring_bitmap_from_range(min, max, step);
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_rank(const roaring_bitmap_t *r, uint32_t x) {
    volatile uint64_t rank = roaring_bitmap_rank(r, x);
    (void)rank; // Suppress unused variable warning
}

static void fuzz_roaring_bitmap_range_cardinality_closed(const roaring_bitmap_t *r, uint32_t range_start, uint32_t range_end) {
    volatile uint64_t cardinality = roaring_bitmap_range_cardinality_closed(r, range_start, range_end);
    (void)cardinality; // Suppress unused variable warning
}

static void fuzz_roaring_bitmap_rank_many(const roaring_bitmap_t *r, const uint32_t *begin, const uint32_t *end) {
    size_t length = end - begin;
    uint64_t *ans = (uint64_t *)malloc(length * sizeof(uint64_t));
    if (ans != NULL) {
        roaring_bitmap_rank_many(r, begin, end, ans);
        free(ans);
    }
}

static void fuzz_roaring_bitmap_get_cardinality(const roaring_bitmap_t *r) {
    volatile uint64_t cardinality = roaring_bitmap_get_cardinality(r);
    (void)cardinality; // Suppress unused variable warning
}

static void fuzz_roaring_bitmap_range_cardinality(const roaring_bitmap_t *r, uint64_t range_start, uint64_t range_end) {
    volatile uint64_t cardinality = roaring_bitmap_range_cardinality(r, range_start, range_end);
    (void)cardinality; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 16) return 0;

    uint64_t min = *(const uint64_t *)Data;
    uint64_t max = *(const uint64_t *)(Data + 8);
    uint32_t step = 1;
    if (Size >= 20) {
        step = *(const uint32_t *)(Data + 16);
    }

    roaring_bitmap_t *bitmap = roaring_bitmap_from_range(min, max, step);
    if (bitmap == NULL) return 0;

    if (Size >= 24) {
        uint32_t x = *(const uint32_t *)(Data + 20);
        fuzz_roaring_bitmap_rank(bitmap, x);
    }

    if (Size >= 32) {
        uint32_t range_start = *(const uint32_t *)(Data + 24);
        uint32_t range_end = *(const uint32_t *)(Data + 28);
        fuzz_roaring_bitmap_range_cardinality_closed(bitmap, range_start, range_end);
    }

    if (Size > 32) {
        const uint32_t *begin = (const uint32_t *)(Data + 32);
        const uint32_t *end = begin + ((Size - 32) / sizeof(uint32_t));
        fuzz_roaring_bitmap_rank_many(bitmap, begin, end);
    }

    fuzz_roaring_bitmap_get_cardinality(bitmap);

    if (Size >= 44) {
        uint64_t range_start = *(const uint64_t *)(Data + 36);
        uint64_t range_end = (Size >= 52) ? *(const uint64_t *)(Data + 44) : range_start + 1;
        fuzz_roaring_bitmap_range_cardinality(bitmap, range_start, range_end);
    }

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
