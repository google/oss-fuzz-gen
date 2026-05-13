#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "roaring/roaring.h"

static void fuzz_roaring_bitmap_add_range_closed(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 8) {
        return;
    }
    uint32_t min = *(uint32_t *)Data;
    uint32_t max = *(uint32_t *)(Data + 4);
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of roaring_bitmap_add_range_closed
    roaring_bitmap_add_range_closed(bitmap, min, 64);
    // End mutation: Producer.REPLACE_ARG_MUTATOR
}

static void fuzz_roaring_bitmap_range_cardinality_closed(const roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 8) {
        return;
    }
    uint32_t range_start = *(uint32_t *)Data;
    uint32_t range_end = *(uint32_t *)(Data + 4);
    roaring_bitmap_range_cardinality_closed(bitmap, range_start, range_end);
}

static void fuzz_roaring_bitmap_add_many(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return;
    }
    size_t n_args = (Size - 4) / 4;
    const uint32_t *vals = (const uint32_t *)(Data + 4);
    roaring_bitmap_add_many(bitmap, n_args, vals);
}

static void fuzz_roaring_bitmap_remove_range_closed(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 8) {
        return;
    }
    uint32_t min = *(uint32_t *)Data;
    uint32_t max = *(uint32_t *)(Data + 4);
    roaring_bitmap_remove_range_closed(bitmap, min, max);
}

static void fuzz_roaring_bitmap_remove(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return;
    }
    uint32_t x = *(uint32_t *)Data;
    roaring_bitmap_remove(bitmap, x);
}

static void fuzz_roaring_bitmap_remove_many(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return;
    }
    size_t n_args = (Size - 4) / 4;
    const uint32_t *vals = (const uint32_t *)(Data + 4);
    roaring_bitmap_remove_many(bitmap, n_args, vals);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    fuzz_roaring_bitmap_add_range_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_range_cardinality_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_add_many(bitmap, Data, Size);
    fuzz_roaring_bitmap_remove_range_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_remove(bitmap, Data, Size);
    fuzz_roaring_bitmap_remove_many(bitmap, Data, Size);

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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
