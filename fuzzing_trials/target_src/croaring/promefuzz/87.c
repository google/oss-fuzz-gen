// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_create_iterator at roaring.h:1143:1 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_copy_uint32_iterator at roaring.h:1205:1 in roaring.h
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_uint32_iterator_copy at roaring.c:1789:28 in roaring.h
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_uint32_iterator_skip at roaring.c:1885:10 in roaring.h
// roaring_uint32_iterator_skip_backward at roaring.c:1912:10 in roaring.h
// roaring_uint32_iterator_move_equalorlarger at roaring.c:1798:6 in roaring.h
// roaring_uint32_iterator_read at roaring.c:1860:10 in roaring.h
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring.h"

static roaring_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    // Create a bitmap and populate it with some data
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;
    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    // Create a random bitmap
    roaring_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) return 0;

    // Create an iterator
    roaring_uint32_iterator_t *iterator = roaring_create_iterator(bitmap);
    if (!iterator) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Fuzz roaring_copy_uint32_iterator
    roaring_uint32_iterator_t *copy1 = roaring_copy_uint32_iterator(iterator);
    if (copy1) roaring_free_uint32_iterator(copy1);

    // Fuzz roaring_uint32_iterator_copy
    roaring_uint32_iterator_t *copy2 = roaring_uint32_iterator_copy(iterator);
    if (copy2) roaring_free_uint32_iterator(copy2);

    // Fuzz roaring_uint32_iterator_skip
    uint32_t skip_count;
    memcpy(&skip_count, Data, sizeof(uint32_t));
    roaring_uint32_iterator_skip(iterator, skip_count);

    // Fuzz roaring_uint32_iterator_skip_backward
    uint32_t skip_back_count;
    memcpy(&skip_back_count, Data, sizeof(uint32_t));
    roaring_uint32_iterator_skip_backward(iterator, skip_back_count);

    // Fuzz roaring_uint32_iterator_move_equalorlarger
    uint32_t move_value;
    memcpy(&move_value, Data, sizeof(uint32_t));
    roaring_uint32_iterator_move_equalorlarger(iterator, move_value);

    // Fuzz roaring_uint32_iterator_read
    uint32_t buffer[256];
    roaring_uint32_iterator_read(iterator, buffer, 256);

    // Clean up
    roaring_free_uint32_iterator(iterator);
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

        LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    