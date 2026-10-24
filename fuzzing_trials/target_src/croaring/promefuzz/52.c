// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_add_range at roaring.h:422:13 in roaring.h
// roaring_bitmap_remove_range at roaring.h:444:13 in roaring.h
// roaring_bitmap_xor at roaring.c:1028:19 in roaring.h
// roaring_bitmap_add_many at roaring.c:134:6 in roaring.h
// roaring_bitmap_remove_range_closed at roaring.c:302:6 in roaring.h
// roaring_bitmap_shrink_to_fit at roaring.c:1467:8 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static void initialize_bitmap(roaring_bitmap_t **bitmap) {
    *bitmap = roaring_bitmap_create();
    if (*bitmap == NULL) {
        exit(1); // Exit if bitmap creation fails
    }
}

static void cleanup_bitmap(roaring_bitmap_t *bitmap) {
    roaring_bitmap_free(bitmap);
}

int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0; // Ensure there's enough data

    roaring_bitmap_t *bitmap1, *bitmap2;
    initialize_bitmap(&bitmap1);
    initialize_bitmap(&bitmap2);

    uint64_t min = *((uint64_t *)Data);
    uint64_t max = *((uint64_t *)(Data + 4));

    // Fuzz roaring_bitmap_add_range
    roaring_bitmap_add_range(bitmap1, min, max);

    // Fuzz roaring_bitmap_remove_range
    roaring_bitmap_remove_range(bitmap1, min, max);

    // Fuzz roaring_bitmap_xor
    roaring_bitmap_t *result = roaring_bitmap_xor(bitmap1, bitmap2);
    if (result != NULL) {
        cleanup_bitmap(result);
    }

    // Fuzz roaring_bitmap_add_many
    if (Size > 8) {
        size_t n_args = (Size - 8) / sizeof(uint32_t);
        const uint32_t *vals = (const uint32_t *)(Data + 8);
        roaring_bitmap_add_many(bitmap1, n_args, vals);
    }

    // Fuzz roaring_bitmap_remove_range_closed
    roaring_bitmap_remove_range_closed(bitmap1, (uint32_t)min, (uint32_t)max);

    // Fuzz roaring_bitmap_shrink_to_fit
    roaring_bitmap_shrink_to_fit(bitmap1);

    cleanup_bitmap(bitmap1);
    cleanup_bitmap(bitmap2);

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

        LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    