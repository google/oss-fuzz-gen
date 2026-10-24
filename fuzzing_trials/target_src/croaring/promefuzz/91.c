// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_set_copy_on_write at roaring.h:106:13 in roaring.h
// roaring_bitmap_and_inplace at roaring.c:812:6 in roaring.h
// roaring_bitmap_get_copy_on_write at roaring.h:103:13 in roaring.h
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
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static roaring_bitmap_t *create_random_bitmap(size_t size, const uint8_t *data) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < size; i++) {
        uint32_t value = data[i];
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_91(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0; // Not enough data to proceed

    size_t half_size = Size / 2;

    // Create two bitmaps
    roaring_bitmap_t *bitmap1 = create_random_bitmap(half_size, Data);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Size - half_size, Data + half_size);

    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_set_copy_on_write
    bool cow = Data[0] % 2 == 0;
    roaring_bitmap_set_copy_on_write(bitmap1, cow);

    // Test roaring_bitmap_and_inplace
    roaring_bitmap_and_inplace(bitmap1, bitmap2);

    // Test roaring_bitmap_get_copy_on_write
    bool is_cow = roaring_bitmap_get_copy_on_write(bitmap1);

    // Test roaring_bitmap_remove_checked
    uint32_t value_to_remove = Data[1];
    bool removed = roaring_bitmap_remove_checked(bitmap1, value_to_remove);

    // Test roaring_contains_shared
    bool contains_shared = roaring_contains_shared(bitmap1);

    // Test roaring_unshare_all
    bool unshared = roaring_unshare_all(bitmap1);

    // Cleanup
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

        LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    