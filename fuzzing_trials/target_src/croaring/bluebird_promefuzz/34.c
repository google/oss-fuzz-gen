#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "roaring/roaring64.h"

static roaring64_bitmap_t* create_dummy_bitmap() {
    roaring64_bitmap_t* bitmap = roaring64_bitmap_create();
    if (bitmap) {
        // Add some dummy values to the bitmap
        for (uint64_t i = 0; i < 100; i += 10) {
            roaring64_bitmap_add(bitmap, i);
        }
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_34(const uint8_t *Data, size_t Size) {
    // Create a dummy bitmap
    roaring64_bitmap_t* bitmap = create_dummy_bitmap();
    if (!bitmap) return 0;

    // Create an iterator pointing to the last element
    roaring64_iterator_t* iterator = roaring64_iterator_create_last(bitmap);
    if (!iterator) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Attempt to move the iterator to the first value greater than or equal to the input value
    if (Size >= sizeof(uint64_t)) {
        uint64_t input_val;
        memcpy(&input_val, Data, sizeof(uint64_t));
        roaring64_iterator_move_equalorlarger(iterator, input_val);
    }

    // Try advancing the iterator
    roaring64_iterator_advance(iterator);

    // Try moving the iterator backwards
    roaring64_iterator_previous(iterator);

    // Create a copy of the iterator
    roaring64_iterator_t* iterator_copy = roaring64_iterator_copy(iterator);
    if (iterator_copy) {
        // Advance the copy to explore different states
        roaring64_iterator_advance(iterator_copy);
        roaring64_iterator_free(iterator_copy);
    }

    // Clean up
    roaring64_iterator_free(iterator);
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
