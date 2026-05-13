// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_of_ptr at roaring.c:195:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_add_range_closed at roaring.c:251:6 in roaring.h
// roaring_bitmap_or_many_heap at roaring_priority_queue.c:200:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_select at roaring.c:2785:6 in roaring.h
// roaring_bitmap_contains_range_closed at roaring.c:2937:6 in roaring.h
// roaring_bitmap_remove_many at roaring.c:696:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include "roaring.h"

static void fuzz_roaring_bitmap_of_ptr(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;
    
    size_t n_args = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_t *bitmap = roaring_bitmap_of_ptr(n_args, vals);
    if (bitmap) {
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_add_range_closed(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    uint32_t min = *(const uint32_t *)Data;
    uint32_t max = *(const uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_add_range_closed(bitmap, min, max);
}

static void fuzz_roaring_bitmap_or_many_heap(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    uint32_t number = *(const uint32_t *)Data;
    if (number == 0 || Size < sizeof(uint32_t) + number * sizeof(roaring_bitmap_t *)) return;

    const roaring_bitmap_t **bitmaps = (const roaring_bitmap_t **)(Data + sizeof(uint32_t));

    roaring_bitmap_t *result = roaring_bitmap_or_many_heap(number, bitmaps);
    if (result) {
        roaring_bitmap_free(result);
    }
}

static void fuzz_roaring_bitmap_select(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    uint32_t rank = *(const uint32_t *)Data;
    uint32_t element;

    roaring_bitmap_select(bitmap, rank, &element);
}

static void fuzz_roaring_bitmap_contains_range_closed(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    uint32_t range_start = *(const uint32_t *)Data;
    uint32_t range_end = *(const uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_contains_range_closed(bitmap, range_start, range_end);
}

static void fuzz_roaring_bitmap_remove_many(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    size_t n_args = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_remove_many(bitmap, n_args, vals);
}

int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size) {
    fuzz_roaring_bitmap_of_ptr(Data, Size);

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    fuzz_roaring_bitmap_add_range_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_select(bitmap, Data, Size);
    fuzz_roaring_bitmap_contains_range_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_remove_many(bitmap, Data, Size);

    roaring_bitmap_free(bitmap);

    fuzz_roaring_bitmap_or_many_heap(Data, Size);

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

        LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    