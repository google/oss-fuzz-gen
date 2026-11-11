// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_init_cleared at roaring.h:61:13 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_iterate at roaring.c:1650:6 in roaring.h
// roaring_bitmap_copy at roaring.c:525:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_remove_checked at roaring.c:659:6 in roaring.h
// roaring_bitmap_remove at roaring.c:634:6 in roaring.h
// roaring_bitmap_clear at roaring.c:562:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "roaring.h"

static bool iterator_function(uint32_t value, void *param) {
    // For fuzzing, we'll just continue iterating.
    return true;
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t) * 2) {
        return 0;
    }

    // Initialize a cleared bitmap
    roaring_bitmap_t bitmap;
    roaring_bitmap_init_cleared(&bitmap);

    // Add some elements to the bitmap
    for (size_t i = 0; i < Size / sizeof(uint32_t); i++) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(&bitmap, value);
    }

    // Test roaring_iterate
    roaring_iterate(&bitmap, iterator_function, NULL);

    // Test roaring_bitmap_copy
    roaring_bitmap_t *copy = roaring_bitmap_copy(&bitmap);
    if (copy) {
        roaring_bitmap_free(copy);
    }

    // Test roaring_bitmap_remove_checked
    uint32_t remove_value;
    memcpy(&remove_value, Data, sizeof(uint32_t));
    roaring_bitmap_remove_checked(&bitmap, remove_value);

    // Test roaring_bitmap_remove
    uint32_t remove_value2;
    memcpy(&remove_value2, Data + sizeof(uint32_t), sizeof(uint32_t));
    roaring_bitmap_remove(&bitmap, remove_value2);

    // Clear the bitmap
    roaring_bitmap_clear(&bitmap);

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

        LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    