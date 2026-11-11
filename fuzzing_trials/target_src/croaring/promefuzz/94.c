// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_set_copy_on_write at roaring.h:106:13 in roaring.h
// roaring_bitmap_get_copy_on_write at roaring.h:103:13 in roaring.h
// roaring_bitmap_and_inplace at roaring.c:812:6 in roaring.h
// roaring_bitmap_remove_checked at roaring.c:659:6 in roaring.h
// roaring_contains_shared at roaring.c:421:6 in roaring.h
// roaring_unshare_all at roaring.c:431:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    size_t num_elements = Size / sizeof(uint32_t);
    for (size_t i = 0; i < num_elements; ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create two bitmaps from input data
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data, Size);

    if (!bitmap1 || !bitmap2) {
        if (bitmap1) roaring_bitmap_free(bitmap1);
        if (bitmap2) roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzz roaring_bitmap_set_copy_on_write
    bool cow = Data[0] % 2;
    roaring_bitmap_set_copy_on_write(bitmap1, cow);

    // Fuzz roaring_bitmap_get_copy_on_write
    bool is_cow = roaring_bitmap_get_copy_on_write(bitmap1);

    // Fuzz roaring_bitmap_and_inplace
    roaring_bitmap_and_inplace(bitmap1, bitmap2);

    // Fuzz roaring_bitmap_remove_checked
    if (Size >= sizeof(uint32_t)) {
        uint32_t value;
        memcpy(&value, Data, sizeof(uint32_t));
        bool removed = roaring_bitmap_remove_checked(bitmap1, value);
    }

    // Fuzz roaring_contains_shared
    bool contains_shared = roaring_contains_shared(bitmap1);

    // Fuzz roaring_unshare_all
    bool unshared = roaring_unshare_all(bitmap1);

    // Clean up
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

        LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    