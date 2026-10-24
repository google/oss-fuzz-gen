// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_read_uint32_iterator at roaring.h:1235:44 in roaring.h
// roaring_uint32_iterator_skip_backward at roaring.c:1912:10 in roaring.h
// roaring_move_uint32_iterator_equalorlarger at roaring.h:1191:1 in roaring.h
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "roaring.h"

static roaring_bitmap_t* create_dummy_bitmap() {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;
    for (uint32_t i = 0; i < 100; i += 2) {
        roaring_bitmap_add(bitmap, i);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_90(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    roaring_bitmap_t *bitmap = create_dummy_bitmap();
    if (!bitmap) return 0;

    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (!iterator) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    uint32_t *buffer = (uint32_t *)malloc(sizeof(uint32_t) * 20); // Ensure buffer is large enough
    if (!buffer) {
        roaring_uint32_iterator_free(iterator);
        roaring_bitmap_free(bitmap);
        return 0;
    }

    uint32_t count = Data[0] % 20; // Limit count to the buffer size
    uint32_t value = *(uint32_t*)Data;

    // Fuzz different API functions
    roaring_read_uint32_iterator(iterator, buffer, count);
    roaring_uint32_iterator_skip_backward(iterator, count);
    roaring_move_uint32_iterator_equalorlarger(iterator, value);

    // Cleanup
    roaring_free_uint32_iterator(iterator); // Deprecated, but tested for compatibility
    free(buffer);
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

        LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    