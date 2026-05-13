// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_of_ptr at roaring.c:195:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_range_cardinality_closed at roaring.c:1374:10 in roaring.h
// roaring_bitmap_add_many at roaring.c:134:6 in roaring.h
// roaring_bitmap_maximum at roaring.c:2771:10 in roaring.h
// roaring_bitmap_remove_many at roaring.c:696:6 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
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
#include <stdio.h>
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

static void fuzz_roaring_bitmap_range_cardinality_closed(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint32_t)) return;

    uint32_t range_start = ((const uint32_t *)Data)[0];
    uint32_t range_end = ((const uint32_t *)Data)[1];

    uint64_t cardinality = roaring_bitmap_range_cardinality_closed(bitmap, range_start, range_end);
    (void)cardinality; // Use the result if needed
}

static void fuzz_roaring_bitmap_add_many(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    size_t n_args = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_add_many(bitmap, n_args, vals);
}

static void fuzz_roaring_bitmap_maximum(roaring_bitmap_t *bitmap) {
    uint32_t max_value = roaring_bitmap_maximum(bitmap);
    (void)max_value; // Use the result if needed
}

static void fuzz_roaring_bitmap_remove_many(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    size_t n_args = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_remove_many(bitmap, n_args, vals);
}

static void fuzz_roaring_bitmap_add(roaring_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    uint32_t value = ((const uint32_t *)Data)[0];
    roaring_bitmap_add(bitmap, value);
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    // Fuzz roaring_bitmap_of_ptr
    fuzz_roaring_bitmap_of_ptr(Data, Size);

    // Create a bitmap to use for other functions
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    // Fuzz other functions with the created bitmap
    fuzz_roaring_bitmap_add_many(bitmap, Data, Size);
    fuzz_roaring_bitmap_range_cardinality_closed(bitmap, Data, Size);
    fuzz_roaring_bitmap_maximum(bitmap);
    fuzz_roaring_bitmap_remove_many(bitmap, Data, Size);
    fuzz_roaring_bitmap_add(bitmap, Data, Size);

    // Clean up
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
    