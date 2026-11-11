// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_free_uint32_iterator at roaring.h:1215:40 in roaring.h
// roaring_copy_uint32_iterator at roaring.h:1205:1 in roaring.h
// roaring_iterator_create at roaring.c:1780:28 in roaring.h
// roaring_previous_uint32_iterator at roaring.h:1176:40 in roaring.h
// roaring_uint32_iterator_previous at roaring.c:1842:6 in roaring.h
// roaring_advance_uint32_iterator at roaring.h:1159:40 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring.h"

static void fuzz_roaring_free_uint32_iterator(roaring_uint32_iterator_t *it) {
    if (it) {
        roaring_free_uint32_iterator(it);
    }
}

static roaring_uint32_iterator_t *fuzz_roaring_copy_uint32_iterator(const roaring_uint32_iterator_t *it) {
    if (it) {
        return roaring_copy_uint32_iterator(it);
    }
    return NULL;
}

static roaring_uint32_iterator_t *fuzz_roaring_iterator_create(const roaring_bitmap_t *r) {
    if (r) {
        return roaring_iterator_create(r);
    }
    return NULL;
}

static bool fuzz_roaring_previous_uint32_iterator(roaring_uint32_iterator_t *it) {
    if (it) {
        return roaring_previous_uint32_iterator(it);
    }
    return false;
}

static bool fuzz_roaring_uint32_iterator_previous(roaring_uint32_iterator_t *it) {
    if (it) {
        return roaring_uint32_iterator_previous(it);
    }
    return false;
}

static bool fuzz_roaring_advance_uint32_iterator(roaring_uint32_iterator_t *it) {
    if (it) {
        return roaring_advance_uint32_iterator(it);
    }
    return false;
}

int LLVMFuzzerTestOneInput_68(const uint8_t *Data, size_t Size) {
    // Create a dummy bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    // Populate the bitmap with some data
    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }

    // Create an iterator for the bitmap
    roaring_uint32_iterator_t *iterator = fuzz_roaring_iterator_create(bitmap);
    if (!iterator) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Make a copy of the iterator
    roaring_uint32_iterator_t *iterator_copy = fuzz_roaring_copy_uint32_iterator(iterator);

    // Traverse the bitmap using the iterator
    while (fuzz_roaring_uint32_iterator_previous(iterator)) {
        // Do nothing, just iterate
    }

    // Try to advance the iterator
    while (fuzz_roaring_advance_uint32_iterator(iterator)) {
        // Do nothing, just iterate
    }

    // Free the iterators
    fuzz_roaring_free_uint32_iterator(iterator);
    fuzz_roaring_free_uint32_iterator(iterator_copy);

    // Free the bitmap
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

        LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    