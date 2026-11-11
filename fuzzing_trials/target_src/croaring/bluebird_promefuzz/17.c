#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *data, size_t size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    // Create two bitmaps from input data
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);
    if (!bitmap1 || !bitmap2) goto cleanup;

    // Test roaring_bitmap_is_strict_subset
    roaring_bitmap_is_strict_subset(bitmap1, bitmap2);
    roaring_bitmap_is_strict_subset(bitmap2, bitmap1);

    // Test roaring_bitmap_contains
    if (Size >= 8) {
        uint32_t value = *(uint32_t *)(Data + Size - 4);
        roaring_bitmap_contains(bitmap1, value);
        roaring_bitmap_contains(bitmap2, value);
    }

    // Test roaring_bitmap_add_checked
    if (Size >= 12) {
        uint32_t value_to_add = *(uint32_t *)(Data + Size - 8);
        roaring_bitmap_add_checked(bitmap1, value_to_add);
        roaring_bitmap_add_checked(bitmap2, value_to_add);
    }

    // Test roaring_bitmap_select
    if (Size >= 16) {
        uint32_t rank = *(uint32_t *)(Data + Size - 12);
        uint32_t element;
        roaring_bitmap_select(bitmap1, rank, &element);
        roaring_bitmap_select(bitmap2, rank, &element);
    }

    // Test roaring_bitmap_contains_range_closed
    if (Size >= 20) {
        uint32_t range_start = *(uint32_t *)(Data + Size - 16);
        uint32_t range_end = *(uint32_t *)(Data + Size - 20);
        roaring_bitmap_contains_range_closed(bitmap1, range_start, range_end);
        roaring_bitmap_contains_range_closed(bitmap2, range_start, range_end);
    }

    // Test roaring_bitmap_intersect
    roaring_bitmap_intersect(bitmap1, bitmap2);

cleanup:
    if (bitmap1) roaring_bitmap_free(bitmap1);
    if (bitmap2) roaring_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
