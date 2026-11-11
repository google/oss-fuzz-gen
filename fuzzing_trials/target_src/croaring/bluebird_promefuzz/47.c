#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "roaring/roaring.h"

static roaring_bitmap_t* initialize_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_47(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    roaring_bitmap_t *bitmap = initialize_bitmap(Data, Size);
    if (!bitmap) return 0;

    // Fuzz roaring_bitmap_set_copy_on_write
    bool cow = Data[0] % 2;
    roaring_bitmap_set_copy_on_write(bitmap, cow);

    // Fuzz roaring_bitmap_add_checked
    uint32_t add_value;
    memcpy(&add_value, Data, sizeof(uint32_t));
    roaring_bitmap_add_checked(bitmap, add_value);

    // Fuzz roaring_bitmap_contains_bulk
    roaring_bulk_context_t context = {0};
    uint32_t bulk_value;
    memcpy(&bulk_value, Data, sizeof(uint32_t));
    roaring_bitmap_contains_bulk(bitmap, &context, bulk_value);

    // Fuzz roaring_bitmap_remove_checked
    uint32_t remove_value;
    memcpy(&remove_value, Data, sizeof(uint32_t));
    roaring_bitmap_remove_checked(bitmap, remove_value);

    // Fuzz roaring_bitmap_select
    uint32_t rank;
    memcpy(&rank, Data, sizeof(uint32_t));
    uint32_t element;
    roaring_bitmap_select(bitmap, rank, &element);

    // Fuzz roaring_bitmap_contains_range_closed
    uint32_t range_start, range_end;
    if (Size >= 2 * sizeof(uint32_t)) {
        memcpy(&range_start, Data, sizeof(uint32_t));
        memcpy(&range_end, Data + sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_contains_range_closed(bitmap, range_start, range_end);
    }

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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
