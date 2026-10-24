// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_of_ptr at roaring.c:195:19 in roaring.h
// roaring_bitmap_of_ptr at roaring.c:195:19 in roaring.h
// roaring_bitmap_and at roaring.c:731:19 in roaring.h
// roaring_bitmap_printf at roaring.c:341:6 in roaring.h
// roaring_bitmap_andnot at roaring.c:1194:19 in roaring.h
// roaring_bitmap_printf at roaring.c:341:6 in roaring.h
// roaring_bitmap_copy at roaring.c:525:19 in roaring.h
// roaring_bitmap_printf at roaring.c:341:6 in roaring.h
// roaring_bitmap_of at roaring.c:201:19 in roaring.h
// roaring_bitmap_printf at roaring.c:341:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "roaring.h"

static void cleanup_bitmap(roaring_bitmap_t *bitmap) {
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract some integers from the input data
    size_t num_ints = Size / sizeof(uint32_t);
    const uint32_t *int_data = (const uint32_t *)Data;

    // Create bitmaps using roaring_bitmap_of_ptr
    roaring_bitmap_t *bitmap1 = roaring_bitmap_of_ptr(num_ints, int_data);
    roaring_bitmap_t *bitmap2 = roaring_bitmap_of_ptr(num_ints, int_data);

    if (bitmap1 == NULL || bitmap2 == NULL) {
        cleanup_bitmap(bitmap1);
        cleanup_bitmap(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_and
    roaring_bitmap_t *and_bitmap = roaring_bitmap_and(bitmap1, bitmap2);
    if (and_bitmap != NULL) {
        roaring_bitmap_printf(and_bitmap);
        cleanup_bitmap(and_bitmap);
    }

    // Test roaring_bitmap_andnot
    roaring_bitmap_t *andnot_bitmap = roaring_bitmap_andnot(bitmap1, bitmap2);
    if (andnot_bitmap != NULL) {
        roaring_bitmap_printf(andnot_bitmap);
        cleanup_bitmap(andnot_bitmap);
    }

    // Test roaring_bitmap_copy
    roaring_bitmap_t *copy_bitmap = roaring_bitmap_copy(bitmap1);
    if (copy_bitmap != NULL) {
        roaring_bitmap_printf(copy_bitmap);
        cleanup_bitmap(copy_bitmap);
    }

    // Test deprecated roaring_bitmap_of
    if (num_ints >= 3) {
        roaring_bitmap_t *of_bitmap = roaring_bitmap_of(3, int_data[0], int_data[1], int_data[2]);
        if (of_bitmap != NULL) {
            roaring_bitmap_printf(of_bitmap);
            cleanup_bitmap(of_bitmap);
        }
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    