// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_remove_run_compression at roaring64.c:981:6 in roaring64.h
// roaring64_bitmap_internal_validate at roaring64.c:1110:6 in roaring64.h
// roaring64_bitmap_equals at roaring64.c:1116:6 in roaring64.h
// roaring64_bitmap_is_subset at roaring64.c:1137:6 in roaring64.h
// roaring64_bitmap_contains at roaring64.c:549:6 in roaring64.h
// roaring64_bitmap_iterate at roaring64.c:2719:6 in roaring64.h
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

static bool dummy_iterator(uint64_t value, void *param) {
    return true; // Continue iteration
}

int LLVMFuzzerTestOneInput_41(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Create two bitmaps for testing
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();
    if (!bitmap1 || !bitmap2) return 0;

    // Insert some values into the bitmaps
    for (size_t i = 0; i < Size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap1, value);
        roaring64_bitmap_add(bitmap2, value + 1); // Slightly different values
    }

    // Test roaring64_bitmap_remove_run_compression
    roaring64_bitmap_remove_run_compression(bitmap1);

    // Test roaring64_bitmap_internal_validate
    const char *reason = NULL;
    roaring64_bitmap_internal_validate(bitmap1, &reason);

    // Test roaring64_bitmap_equals
    roaring64_bitmap_equals(bitmap1, bitmap2);

    // Test roaring64_bitmap_is_subset
    roaring64_bitmap_is_subset(bitmap1, bitmap2);

    // Test roaring64_bitmap_contains
    if (Size >= sizeof(uint64_t)) {
        uint64_t test_value;
        memcpy(&test_value, Data, sizeof(uint64_t));
        roaring64_bitmap_contains(bitmap1, test_value);
    }

    // Test roaring64_bitmap_iterate
    roaring64_bitmap_iterate(bitmap1, dummy_iterator, NULL);

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

        LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    