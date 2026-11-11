// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_is_empty at roaring64.c:957:6 in roaring64.h
// roaring64_bitmap_internal_validate at roaring64.c:1110:6 in roaring64.h
// roaring64_bitmap_get_index at roaring64.c:686:6 in roaring64.h
// roaring64_bitmap_run_optimize at roaring64.c:1001:6 in roaring64.h
// roaring64_bitmap_contains at roaring64.c:549:6 in roaring64.h
// roaring64_bitmap_iterate at roaring64.c:2719:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring64.h"

static bool dummy_iterator(uint64_t value, void *param) {
    return true; // Continue iteration
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    // Initialize a roaring bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return 0;

    // Add some data to the bitmap
    for (size_t i = 0; i < Size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Fuzz roaring64_bitmap_is_empty
    (void)roaring64_bitmap_is_empty(bitmap);

    // Fuzz roaring64_bitmap_internal_validate
    const char *reason = NULL;
    (void)roaring64_bitmap_internal_validate(bitmap, &reason);

    // Fuzz roaring64_bitmap_get_index
    if (Size >= sizeof(uint64_t)) {
        uint64_t val;
        memcpy(&val, Data, sizeof(uint64_t));
        uint64_t out_index;
        (void)roaring64_bitmap_get_index(bitmap, val, &out_index);
    }

    // Fuzz roaring64_bitmap_run_optimize
    (void)roaring64_bitmap_run_optimize(bitmap);

    // Fuzz roaring64_bitmap_contains
    if (Size >= sizeof(uint64_t)) {
        uint64_t val;
        memcpy(&val, Data, sizeof(uint64_t));
        (void)roaring64_bitmap_contains(bitmap, val);
    }

    // Fuzz roaring64_bitmap_iterate
    (void)roaring64_bitmap_iterate(bitmap, dummy_iterator, NULL);

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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    