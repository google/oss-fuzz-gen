// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_xor at roaring.c:1028:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add_range_closed at roaring.c:251:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_remove_range_closed at roaring.c:302:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add_bulk at roaring.c:159:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_flip_inplace_closed at roaring.c:2175:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_flip_closed at roaring.c:2114:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static void fuzz_roaring_bitmap_xor(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(roaring_bitmap_t)) return;

    roaring_bitmap_t *r1 = roaring_bitmap_create();
    roaring_bitmap_t *r2 = roaring_bitmap_create();
    if (!r1 || !r2) {
        roaring_bitmap_free(r1);
        roaring_bitmap_free(r2);
        return;
    }

    roaring_bitmap_t *result = roaring_bitmap_xor(r1, r2);
    if (result != NULL) {
        roaring_bitmap_free(result);
    }

    roaring_bitmap_free(r1);
    roaring_bitmap_free(r2);
}

static void fuzz_roaring_bitmap_add_range_closed(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    roaring_bitmap_t *r = roaring_bitmap_create();
    if (!r) return;

    uint32_t min = *(uint32_t *)Data;
    uint32_t max = *(uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_add_range_closed(r, min, max);
    roaring_bitmap_free(r);
}

static void fuzz_roaring_bitmap_remove_range_closed(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    roaring_bitmap_t *r = roaring_bitmap_create();
    if (!r) return;

    uint32_t min = *(uint32_t *)Data;
    uint32_t max = *(uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_remove_range_closed(r, min, max);
    roaring_bitmap_free(r);
}

static void fuzz_roaring_bitmap_add_bulk(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(roaring_bulk_context_t) + sizeof(uint32_t)) return;

    roaring_bitmap_t *r = roaring_bitmap_create();
    if (!r) return;

    roaring_bulk_context_t context = {0};
    uint32_t val = *(uint32_t *)(Data + sizeof(roaring_bulk_context_t));

    roaring_bitmap_add_bulk(r, &context, val);
    roaring_bitmap_free(r);
}

static void fuzz_roaring_bitmap_flip_inplace_closed(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    roaring_bitmap_t *r1 = roaring_bitmap_create();
    if (!r1) return;

    uint32_t range_start = *(uint32_t *)Data;
    uint32_t range_end = *(uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_flip_inplace_closed(r1, range_start, range_end);
    roaring_bitmap_free(r1);
}

static void fuzz_roaring_bitmap_flip_closed(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    roaring_bitmap_t *x1 = roaring_bitmap_create();
    if (!x1) return;

    uint32_t range_start = *(uint32_t *)Data;
    uint32_t range_end = *(uint32_t *)(Data + sizeof(uint32_t));

    roaring_bitmap_t *result = roaring_bitmap_flip_closed(x1, range_start, range_end);
    if (result != NULL) {
        roaring_bitmap_free(result);
    }

    roaring_bitmap_free(x1);
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    fuzz_roaring_bitmap_xor(Data, Size);
    fuzz_roaring_bitmap_add_range_closed(Data, Size);
    fuzz_roaring_bitmap_remove_range_closed(Data, Size);
    fuzz_roaring_bitmap_add_bulk(Data, Size);
    fuzz_roaring_bitmap_flip_inplace_closed(Data, Size);
    fuzz_roaring_bitmap_flip_closed(Data, Size);

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

        LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    