// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_uint32_iterator_copy at roaring.c:1789:28 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_init_iterator at roaring.h:1112:40 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        uint32_t value = (uint32_t)Data[i];
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) return 0;

    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (iterator) {
        roaring_uint32_iterator_t *copy_iterator = roaring_uint32_iterator_copy(iterator);
        if (copy_iterator) {
            roaring_uint32_iterator_free(copy_iterator);
        }

        roaring_free_uint32_iterator(iterator);
    }

    roaring_uint32_iterator_t new_iterator;
    roaring_init_iterator(bitmap, &new_iterator);

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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    