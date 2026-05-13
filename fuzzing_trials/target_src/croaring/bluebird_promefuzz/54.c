#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "roaring/roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size, size_t *offset) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;

    while (*offset + sizeof(uint64_t) <= Size) {
        uint64_t value = *(uint64_t *)(Data + *offset);
        *offset += sizeof(uint64_t);
        roaring64_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    size_t offset = 0;

    // Create two random bitmaps from the input data
    roaring64_bitmap_t *bitmap1 = create_random_bitmap(Data, Size, &offset);
    roaring64_bitmap_t *bitmap2 = create_random_bitmap(Data, Size, &offset);

    if (!bitmap1 || !bitmap2) {
        if (bitmap1) roaring64_bitmap_free(bitmap1);
        if (bitmap2) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzz roaring64_bitmap_or_cardinality
    uint64_t or_cardinality = roaring64_bitmap_or_cardinality(bitmap1, bitmap2);
    (void)or_cardinality; // Use the result to prevent unused variable warning

    // Fuzz roaring64_bitmap_and_cardinality
    uint64_t and_cardinality = roaring64_bitmap_and_cardinality(bitmap1, bitmap2);
    (void)and_cardinality;

    // Fuzz roaring64_bitmap_xor_cardinality
    uint64_t xor_cardinality = roaring64_bitmap_xor_cardinality(bitmap1, bitmap2);
    (void)xor_cardinality;

    // Fuzz roaring64_bitmap_andnot_cardinality
    uint64_t andnot_cardinality = roaring64_bitmap_andnot_cardinality(bitmap1, bitmap2);
    (void)andnot_cardinality;

    // Fuzz roaring64_bitmap_add_checked
    if (offset + sizeof(uint64_t) <= Size) {
        uint64_t value = *(uint64_t *)(Data + offset);
        bool added = roaring64_bitmap_add_checked(bitmap1, value);
        (void)added;
    }

    // Fuzz roaring64_bitmap_range_closed_cardinality
    if (offset + sizeof(uint64_t) * 2 <= Size) {
        uint64_t min = *(uint64_t *)(Data + offset);
        uint64_t max = *(uint64_t *)(Data + offset + sizeof(uint64_t));
        uint64_t range_cardinality = roaring64_bitmap_range_closed_cardinality(bitmap1, min, max);
        (void)range_cardinality;
    }

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
