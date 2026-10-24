#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring/roaring.h"

static roaring_uint32_iterator_t *initialize_iterator(const uint8_t *Data, size_t Size, roaring_bitmap_t **bitmap_out) {
    // Create a bitmap and populate it with data
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size / 4; i++) {
        uint32_t value = ((uint32_t *)Data)[i];
        roaring_bitmap_add(bitmap, value);
    }

    // Create an iterator for the bitmap
    roaring_uint32_iterator_t *it = roaring_create_iterator(bitmap);
    *bitmap_out = bitmap; // Return the bitmap so it can be freed later
    return it;
}

static void fuzz_roaring_uint32_iterator_advance(roaring_uint32_iterator_t *it) {
    while (roaring_uint32_iterator_advance(it)) {
        // Iterate until the end
    }
}

static void fuzz_roaring_copy_uint32_iterator(roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *copy_it = roaring_copy_uint32_iterator(it);
    if (copy_it) {
        roaring_free_uint32_iterator(copy_it);
    }
}

static void fuzz_roaring_uint32_iterator_copy(roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *copy_it = roaring_uint32_iterator_copy(it);
    if (copy_it) {
        roaring_free_uint32_iterator(copy_it);
    }
}

static void fuzz_roaring_move_uint32_iterator_equalorlarger(roaring_uint32_iterator_t *it, uint32_t val) {
    roaring_move_uint32_iterator_equalorlarger(it, val);
}

static void fuzz_roaring_uint32_iterator_previous(roaring_uint32_iterator_t *it) {
    while (roaring_uint32_iterator_previous(it)) {
        // Iterate in reverse until the beginning
    }
}

static void fuzz_roaring_advance_uint32_iterator(roaring_uint32_iterator_t *it) {
    while (roaring_advance_uint32_iterator(it)) {
        // Iterate until the end
    }
}

int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = NULL;
    // Initialize iterator
    roaring_uint32_iterator_t *it = initialize_iterator(Data, Size, &bitmap);
    if (!it) return 0;

    // Fuzz different functions
    fuzz_roaring_uint32_iterator_advance(it);
    fuzz_roaring_copy_uint32_iterator(it);
    fuzz_roaring_uint32_iterator_copy(it);
    fuzz_roaring_move_uint32_iterator_equalorlarger(it, 0);
    fuzz_roaring_uint32_iterator_previous(it);
    fuzz_roaring_advance_uint32_iterator(it);

    // Clean up
    roaring_free_uint32_iterator(it);
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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
