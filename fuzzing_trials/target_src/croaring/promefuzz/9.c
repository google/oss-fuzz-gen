// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add_offset_signed at roaring64.c:1959:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_shrink_to_fit at roaring64.c:1033:8 in roaring64.h
// roaring64_bitmap_frozen_size_in_bytes at roaring64.c:2415:8 in roaring64.h
// roaring64_bitmap_portable_size_in_bytes at roaring64.c:2106:8 in roaring64.h
// roaring64_bitmap_flip_closed_inplace at roaring64.c:1928:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring64.h"

static void initialize_bitmap(roaring64_bitmap_t *bitmap) {
    // Initialize the bitmap with some default values for fuzzing
    roaring64_bitmap_add(bitmap, 1);
    roaring64_bitmap_add(bitmap, 1000);
    roaring64_bitmap_add(bitmap, 1000000);
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < 9) return 0; // Ensure enough data for offset

    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return 0;

    initialize_bitmap(bitmap);

    // Fuzz roaring64_bitmap_add_offset_signed
    bool positive = Data[0] % 2 == 0;
    uint64_t offset = *((uint64_t *)(Data + 1));
    roaring64_bitmap_t *shifted_bitmap = roaring64_bitmap_add_offset_signed(bitmap, positive, offset);
    if (shifted_bitmap) {
        roaring64_bitmap_free(shifted_bitmap);
    }

    // Fuzz roaring64_bitmap_shrink_to_fit
    size_t bytes_freed = roaring64_bitmap_shrink_to_fit(bitmap);

    // Fuzz roaring64_bitmap_frozen_size_in_bytes
    size_t frozen_size = roaring64_bitmap_frozen_size_in_bytes(bitmap);

    // Fuzz roaring64_bitmap_portable_size_in_bytes
    size_t portable_size = roaring64_bitmap_portable_size_in_bytes(bitmap);

    // Fuzz roaring64_bitmap_flip_closed_inplace
    if (Size >= 25) { // Ensure enough data for min and max
        uint64_t min = *((uint64_t *)(Data + 9));
        uint64_t max = *((uint64_t *)(Data + 17));
        if (min <= max) {
            roaring64_bitmap_flip_closed_inplace(bitmap, min, max);
        }
    }

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

        LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    