// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create_with_capacity at roaring.c:86:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_add_checked at roaring.c:594:6 in roaring.h
// roaring_bitmap_contains at roaring.h:467:13 in roaring.h
// roaring_bitmap_add_checked at roaring.c:594:6 in roaring.h
// roaring_bitmap_contains at roaring.h:467:13 in roaring.h
// roaring_bitmap_equals at roaring.c:1943:6 in roaring.h
// roaring_bitmap_intersect at roaring.c:2809:6 in roaring.h
// roaring_bitmap_copy at roaring.c:525:19 in roaring.h
// roaring_bitmap_equals at roaring.c:1943:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring.h"

static void initialize_bitmap(roaring_bitmap_t **bitmap, uint32_t capacity) {
    *bitmap = roaring_bitmap_create_with_capacity(capacity);
    if (*bitmap == NULL) {
        fprintf(stderr, "Failed to initialize bitmap with capacity %u\n", capacity);
        exit(EXIT_FAILURE);
    }
}

static void cleanup_bitmap(roaring_bitmap_t *bitmap) {
    roaring_bitmap_free(bitmap);
}

int LLVMFuzzerTestOneInput_44(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0; // Need at least 4 bytes to form a uint32_t
    }

    uint32_t capacity = *((uint32_t *)Data);
    Data += 4;
    Size -= 4;

    roaring_bitmap_t *bitmap1, *bitmap2;
    initialize_bitmap(&bitmap1, capacity);
    initialize_bitmap(&bitmap2, capacity);

    if (Size >= 4) {
        uint32_t value = *((uint32_t *)Data);
        roaring_bitmap_add_checked(bitmap1, value);
        roaring_bitmap_contains(bitmap1, value);
        roaring_bitmap_add_checked(bitmap2, value);
        roaring_bitmap_contains(bitmap2, value);
    }

    roaring_bitmap_equals(bitmap1, bitmap2);
    roaring_bitmap_intersect(bitmap1, bitmap2);

    roaring_bitmap_t *copy = roaring_bitmap_copy(bitmap1);
    if (copy) {
        roaring_bitmap_equals(bitmap1, copy);
        cleanup_bitmap(copy);
    }

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

        LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    