#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring/roaring64.h"

static roaring64_bitmap_t* initialize_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size / sizeof(uint64_t); ++i) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    roaring64_bitmap_t *bitmap = initialize_bitmap(Data, Size);
    if (!bitmap) return 0;

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));

    // Test roaring64_bitmap_maximum
    uint64_t max_value = roaring64_bitmap_maximum(bitmap);

    // Test roaring64_bitmap_remove_checked
    bool removed = roaring64_bitmap_remove_checked(bitmap, value);

    // Test roaring64_bitmap_get_index
    uint64_t index;
    bool found = roaring64_bitmap_get_index(bitmap, value, &index);

    // Test roaring64_bitmap_add_checked
    bool added = roaring64_bitmap_add_checked(bitmap, value);

    // Test roaring64_bitmap_contains
    bool contains = roaring64_bitmap_contains(bitmap, value);

    // Test roaring64_bitmap_select
    uint64_t element;
    bool selected = roaring64_bitmap_select(bitmap, 0, &element);

    // Cleanup
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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
