// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add_range at roaring64.c:510:6 in roaring64.h
// roaring64_bitmap_remove at roaring64.c:744:6 in roaring64.h
// roaring64_bitmap_intersect_with_range at roaring64.c:1363:6 in roaring64.h
// roaring64_bitmap_select at roaring64.c:638:6 in roaring64.h
// roaring64_bitmap_contains_bulk at roaring64.c:617:6 in roaring64.h
// roaring64_bitmap_add_bulk at roaring64.c:446:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "roaring64.h"

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) * 4) {
        return 0;
    }

    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Extracting values from the data
    uint64_t min_add = *((uint64_t *)Data);
    uint64_t max_add = *((uint64_t *)(Data + sizeof(uint64_t)));
    uint64_t value_remove = *((uint64_t *)(Data + 2 * sizeof(uint64_t)));
    uint64_t rank_select = *((uint64_t *)(Data + 3 * sizeof(uint64_t)));

    // Fuzz roaring64_bitmap_add_range
    roaring64_bitmap_add_range(bitmap, min_add, max_add);

    // Fuzz roaring64_bitmap_remove
    roaring64_bitmap_remove(bitmap, value_remove);

    // Fuzz roaring64_bitmap_intersect_with_range
    bool intersects = roaring64_bitmap_intersect_with_range(bitmap, min_add, max_add);

    // Fuzz roaring64_bitmap_select
    uint64_t element;
    bool select_result = roaring64_bitmap_select(bitmap, rank_select, &element);

    // Fuzz roaring64_bitmap_contains_bulk
    roaring64_bulk_context_t context = {0};
    bool contains_bulk = roaring64_bitmap_contains_bulk(bitmap, &context, value_remove);

    // Fuzz roaring64_bitmap_add_bulk
    roaring64_bitmap_add_bulk(bitmap, &context, value_remove);

    // Clean up
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

        LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    