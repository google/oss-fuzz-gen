// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_flip_inplace at roaring64.c:1920:6 in roaring64.h
// roaring64_bitmap_add_range_closed at roaring64.c:518:6 in roaring64.h
// roaring64_bitmap_flip_closed at roaring64.c:1859:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_flip at roaring64.c:1851:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_flip_closed_inplace at roaring64.c:1928:6 in roaring64.h
// roaring64_bitmap_remove_range_closed at roaring64.c:855:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring64.h"

static roaring64_bitmap_t* create_random_bitmap() {
    roaring64_bitmap_t *r = roaring64_bitmap_create();
    if (!r) return NULL;

    uint64_t num_elements = rand() % 1000;
    for (uint64_t i = 0; i < num_elements; ++i) {
        roaring64_bitmap_add(r, rand() % 10000);
    }
    return r;
}

static void fuzz_flip_inplace(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_flip_inplace(r, min, max);
}

static void fuzz_add_range_closed(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_add_range_closed(r, min, max);
}

static void fuzz_flip_closed(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_t *new_r = roaring64_bitmap_flip_closed(r, min, max);
    if (new_r) {
        roaring64_bitmap_free(new_r);
    }
}

static void fuzz_flip(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_t *new_r = roaring64_bitmap_flip(r, min, max);
    if (new_r) {
        roaring64_bitmap_free(new_r);
    }
}

static void fuzz_flip_closed_inplace(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_flip_closed_inplace(r, min, max);
}

static void fuzz_remove_range_closed(roaring64_bitmap_t *r, const uint8_t *Data, size_t Size) {
    if (Size < 16) return;
    uint64_t min = *((uint64_t*)Data);
    uint64_t max = *((uint64_t*)(Data + 8));
    roaring64_bitmap_remove_range_closed(r, min, max);
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = create_random_bitmap();
    if (!bitmap) return 0;

    fuzz_flip_inplace(bitmap, Data, Size);
    fuzz_add_range_closed(bitmap, Data, Size);
    fuzz_flip_closed(bitmap, Data, Size);
    fuzz_flip(bitmap, Data, Size);
    fuzz_flip_closed_inplace(bitmap, Data, Size);
    fuzz_remove_range_closed(bitmap, Data, Size);

    roaring64_bitmap_free(bitmap);
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

        LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    