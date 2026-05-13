#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some values to the bitmap for testing
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Ensure that the range is valid (start <= end)
    uint64_t start = 0;
    uint64_t end = 0;

    if (size >= 16) {
        // Use the first 8 bytes for start and the next 8 bytes for end
        start = *((uint64_t *)data);
        end = *((uint64_t *)(data + 8));
    } else if (size >= 8) {
        // Use the first 8 bytes for start and set end to start + size
        start = *((uint64_t *)data);
        end = start + size;
    } else {
        // Set start to 0 and end to size
        end = size;
    }

    // Call the function-under-test
    bool result = roaring_bitmap_intersect_with_range(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_90(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
