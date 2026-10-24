// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_copy_uint32_iterator at roaring.h:1205:1 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_create_iterator at roaring.h:1143:1 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_iterator_init at roaring.c:1766:6 in roaring.h
// roaring_iterator_init_last at roaring.c:1773:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring.h"

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    // Create a bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    // Add some data to the bitmap
    for (size_t i = 0; i < Size / sizeof(uint32_t); i++) {
        uint32_t value = ((uint32_t *)Data)[i];
        roaring_bitmap_add(bitmap, value);
    }

    // Create an iterator using roaring_iterator_create
    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (iterator) {
        // Use roaring_copy_uint32_iterator
        roaring_uint32_iterator_t *copy_iterator = roaring_copy_uint32_iterator(iterator);
        if (copy_iterator) {
            roaring_uint32_iterator_free(copy_iterator);
        }
        roaring_uint32_iterator_free(iterator);
    }

    // Deprecated: Create an iterator using roaring_create_iterator
    roaring_uint32_iterator_t *deprecated_iterator = roaring_create_iterator(bitmap);
    if (deprecated_iterator) {
        roaring_uint32_iterator_free(deprecated_iterator);
    }

    // Initialize an iterator using roaring_iterator_init
    roaring_uint32_iterator_t init_iterator;
    roaring_iterator_init(bitmap, &init_iterator);

    // Initialize an iterator to the last element using roaring_iterator_init_last
    roaring_uint32_iterator_t last_iterator;
    roaring_iterator_init_last(bitmap, &last_iterator);

    // Clean up
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

        LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    