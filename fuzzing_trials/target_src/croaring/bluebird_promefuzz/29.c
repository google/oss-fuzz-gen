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
#include "roaring/roaring.h"

static roaring_uint32_iterator_t *create_dummy_iterator(roaring_bitmap_t **out_bitmap) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;
    roaring_bitmap_add_range_closed(bitmap, 0, 1000);
    roaring_uint32_iterator_t *it = roaring_create_iterator(bitmap);
    *out_bitmap = bitmap; // Keep the bitmap alive for the iterator's lifetime
    return it;
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    uint32_t count = *((uint32_t *)Data);
    bool result;
    uint32_t buffer[100];

    roaring_bitmap_t *bitmap = NULL;
    roaring_uint32_iterator_t *it = create_dummy_iterator(&bitmap);
    if (!it || !bitmap) return 0;

    // Test roaring_copy_uint32_iterator
    roaring_uint32_iterator_t *copied_it = roaring_copy_uint32_iterator(it);
    if (copied_it) {
        roaring_free_uint32_iterator(copied_it);
    }

    // Test roaring_uint32_iterator_skip_backward
    uint32_t skipped_backward = roaring_uint32_iterator_skip_backward(it, count);

    // Test roaring_uint32_iterator_copy
    roaring_uint32_iterator_t *copied_it2 = roaring_uint32_iterator_copy(it);
    if (copied_it2) {
        roaring_free_uint32_iterator(copied_it2);
    }

    // Test roaring_uint32_iterator_skip
    uint32_t skipped_forward = roaring_uint32_iterator_skip(it, count);

    // Test roaring_uint32_iterator_move_equalorlarger
    result = roaring_uint32_iterator_move_equalorlarger(it, count);

    // Ensure the buffer size does not exceed its capacity
    uint32_t max_read_count = sizeof(buffer) / sizeof(buffer[0]);
    uint32_t read_count = roaring_uint32_iterator_read(it, buffer, count > max_read_count ? max_read_count : count);

    roaring_free_uint32_iterator(it);
    roaring_bitmap_free(bitmap); // Free the bitmap after the iterator is done
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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
