// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_copy_uint32_iterator at roaring.h:1205:1 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_uint32_iterator_skip_backward at roaring.c:1912:10 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_init_iterator_last at roaring.h:1126:40 in roaring.h
// roaring_iterator_init_last at roaring.c:1773:6 in roaring.h
// roaring_iterator_init at roaring.c:1766:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_uint32_iterator_free at roaring.c:1935:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring.h"

static void fuzz_roaring_copy_uint32_iterator(const roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *copy = roaring_copy_uint32_iterator(it);
    if (copy) {
        roaring_uint32_iterator_free(copy);
    }
}

static void fuzz_roaring_uint32_iterator_skip_backward(roaring_uint32_iterator_t *it, uint32_t count) {
    uint32_t skipped = roaring_uint32_iterator_skip_backward(it, count);
    (void)skipped; // Suppress unused variable warning
}

static void fuzz_roaring_iterator_create(const roaring_bitmap_t *bitmap) {
    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (iterator) {
        roaring_uint32_iterator_free(iterator);
    }
}

static void fuzz_roaring_init_iterator_last(const roaring_bitmap_t *bitmap) {
    roaring_uint32_iterator_t newit;
    roaring_init_iterator_last(bitmap, &newit);
}

static void fuzz_roaring_iterator_init_last(const roaring_bitmap_t *bitmap) {
    roaring_uint32_iterator_t newit;
    roaring_iterator_init_last(bitmap, &newit);
}

static void fuzz_roaring_iterator_init(const roaring_bitmap_t *bitmap) {
    roaring_uint32_iterator_t newit;
    roaring_iterator_init(bitmap, &newit);
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(roaring_bitmap_t)) {
        return 0;
    }

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Populate the bitmap with some values for testing
    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }

    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (iterator) {
        fuzz_roaring_copy_uint32_iterator(iterator);
        fuzz_roaring_uint32_iterator_skip_backward(iterator, Data[0] % 100);
        roaring_uint32_iterator_free(iterator);
    }

    fuzz_roaring_iterator_create(bitmap);
    fuzz_roaring_init_iterator_last(bitmap);
    fuzz_roaring_iterator_init_last(bitmap);
    fuzz_roaring_iterator_init(bitmap);

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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    