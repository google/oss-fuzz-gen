#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
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

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create bitmaps from input data
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size - Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzz roaring_bitmap_add_offset
    int64_t offset = (int64_t)Data[0];
    roaring_bitmap_t *offset_bitmap = roaring_bitmap_add_offset(bitmap1, offset);
    if (offset_bitmap) {
        roaring_bitmap_free(offset_bitmap);
    }

    // Fuzz roaring_bitmap_get_index
    uint32_t x = (uint32_t)Data[0];
    int64_t index = roaring_bitmap_get_index(bitmap1, x);

    // Fuzz roaring_bitmap_or
    roaring_bitmap_t *or_bitmap = roaring_bitmap_or(bitmap1, bitmap2);
    if (or_bitmap) {
        roaring_bitmap_free(or_bitmap);
    }

    // Fuzz roaring_bitmap_add_range_closed
    uint32_t min = (uint32_t)Data[0];
    uint32_t max = (uint32_t)Data[Size - 1];
    roaring_bitmap_add_range_closed(bitmap1, min, max);

    // Fuzz roaring_bitmap_select
    uint32_t element;
    bool select_success = roaring_bitmap_select(bitmap1, x, &element);

    // Fuzz roaring_bitmap_create_with_capacity
    roaring_bitmap_t *capacity_bitmap = roaring_bitmap_create_with_capacity((uint32_t)Data[0]);
    if (capacity_bitmap) {
        roaring_bitmap_free(capacity_bitmap);
    }

    // Cleanup
    roaring_bitmap_free(bitmap1);
    roaring_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
