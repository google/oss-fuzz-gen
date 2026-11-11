// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_jaccard_index at roaring64.c:1377:8 in roaring64.h
// roaring64_bitmap_clear at roaring64.c:888:6 in roaring64.h
// roaring64_bitmap_andnot at roaring64.c:1653:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_get_index at roaring64.c:686:6 in roaring64.h
// roaring64_bitmap_frozen_size_in_bytes at roaring64.c:2415:8 in roaring64.h
// roaring64_bitmap_frozen_serialize at roaring64.c:2493:8 in roaring64.h
// roaring64_bitmap_frozen_view at roaring64.c:2609:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_statistics at roaring64.c:1060:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return NULL;
    
    size_t num_elements = Size / sizeof(uint64_t);
    for (size_t i = 0; i < num_elements; i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_74(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Create two random bitmaps
    roaring64_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring64_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring64_bitmap_jaccard_index
    double jaccard_index = roaring64_bitmap_jaccard_index(bitmap1, bitmap2);

    // Test roaring64_bitmap_clear
    roaring64_bitmap_clear(bitmap1);

    // Test roaring64_bitmap_andnot
    roaring64_bitmap_t *andnot_bitmap = roaring64_bitmap_andnot(bitmap1, bitmap2);
    roaring64_bitmap_free(andnot_bitmap);

    // Test roaring64_bitmap_get_index
    uint64_t out_index;
    bool found = roaring64_bitmap_get_index(bitmap2, *(uint64_t*)Data, &out_index);

    // Prepare buffer for roaring64_bitmap_frozen_view
    size_t buffer_size = roaring64_bitmap_frozen_size_in_bytes(bitmap2);
    char *buffer = (char *)malloc(buffer_size);
    if (buffer) {
        roaring64_bitmap_frozen_serialize(bitmap2, buffer);
        roaring64_bitmap_t *frozen_view = roaring64_bitmap_frozen_view(buffer, buffer_size);
        roaring64_bitmap_free(frozen_view);
        free(buffer);
    }

    // Test roaring64_bitmap_statistics
    roaring64_statistics_t stats;
    roaring64_bitmap_statistics(bitmap2, &stats);

    // Cleanup
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

        LLVMFuzzerTestOneInput_74(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    