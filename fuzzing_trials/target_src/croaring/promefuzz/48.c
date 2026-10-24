// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_run_optimize at roaring.c:1449:6 in roaring.h
// roaring_bitmap_internal_validate at roaring.c:454:6 in roaring.h
// roaring_bitmap_remove_run_compression at roaring.c:1483:6 in roaring.h
// roaring_bitmap_contains at roaring.h:467:13 in roaring.h
// roaring_bitmap_add_checked at roaring.c:594:6 in roaring.h
// roaring_bitmap_intersect_with_range at roaring.c:2840:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include "roaring.h"

static roaring_bitmap_t* initialize_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) return NULL;

    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value = ((uint32_t*)Data)[i];
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    roaring_bitmap_t *bitmap = initialize_bitmap(Data, Size);
    if (bitmap == NULL) return 0;

    const char *reason = NULL;

    // Fuzz roaring_bitmap_run_optimize
    bool optimized = roaring_bitmap_run_optimize(bitmap);

    // Fuzz roaring_bitmap_internal_validate
    bool valid = roaring_bitmap_internal_validate(bitmap, &reason);
    if (!valid && reason) {
        printf("Validation failed: %s\n", reason);
    }

    // Fuzz roaring_bitmap_remove_run_compression
    bool compression_removed = roaring_bitmap_remove_run_compression(bitmap);

    // Fuzz roaring_bitmap_contains
    uint32_t check_value = ((uint32_t*)Data)[0];
    bool contains = roaring_bitmap_contains(bitmap, check_value);

    // Fuzz roaring_bitmap_add_checked
    bool added = roaring_bitmap_add_checked(bitmap, check_value);

    // Fuzz roaring_bitmap_intersect_with_range
    uint64_t range_start = 0;
    uint64_t range_end = ((uint64_t)check_value) + 100;
    bool intersects = roaring_bitmap_intersect_with_range(bitmap, range_start, range_end);

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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    