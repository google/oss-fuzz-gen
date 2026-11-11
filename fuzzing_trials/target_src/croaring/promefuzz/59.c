// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_iterator_create_last at roaring64.c:2749:23 in roaring64.h
// roaring64_iterator_reinit_last at roaring64.c:2761:6 in roaring64.h
// roaring64_iterator_copy at roaring64.c:2766:23 in roaring64.h
// roaring64_iterator_free at roaring64.c:2773:6 in roaring64.h
// roaring64_iterator_reinit at roaring64.c:2756:6 in roaring64.h
// roaring64_iterator_free at roaring64.c:2773:6 in roaring64.h
// roaring64_iterator_create at roaring64.c:2743:23 in roaring64.h
// roaring64_iterator_free at roaring64.c:2773:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "roaring64.h"

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    // Create a new Roaring bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Attempt to add data to the bitmap if size is sufficient
    if (Size >= sizeof(uint64_t)) {
        uint64_t value;
        for (size_t i = 0; i + sizeof(uint64_t) <= Size; i += sizeof(uint64_t)) {
            memcpy(&value, Data + i, sizeof(uint64_t));
            roaring64_bitmap_add(bitmap, value);
        }
    }

    // Create an iterator pointing to the last element
    roaring64_iterator_t *iterator_last = roaring64_iterator_create_last(bitmap);
    if (iterator_last) {
        // Reinitialize the iterator to point to the last element
        roaring64_iterator_reinit_last(bitmap, iterator_last);

        // Create a copy of the iterator
        roaring64_iterator_t *iterator_copy = roaring64_iterator_copy(iterator_last);
        if (iterator_copy) {
            // Free the copied iterator
            roaring64_iterator_free(iterator_copy);
        }

        // Reinitialize the iterator to point to the first element
        roaring64_iterator_reinit(bitmap, iterator_last);

        // Free the original iterator
        roaring64_iterator_free(iterator_last);
    }

    // Create an iterator pointing to the first element
    roaring64_iterator_t *iterator_first = roaring64_iterator_create(bitmap);
    if (iterator_first) {
        // Free the first iterator
        roaring64_iterator_free(iterator_first);
    }

    // Clean up
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

        LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    