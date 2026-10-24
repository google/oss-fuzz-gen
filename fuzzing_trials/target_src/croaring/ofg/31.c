#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    uint64_t range_start = 0;
    uint64_t range_end = 0;

    // Ensure we have enough data to set meaningful range values
    if (size >= 16) {
        // Use the first 8 bytes for range_start
        range_start = *((const uint64_t *)data);

        // Use the next 8 bytes for range_end
        range_end = *((const uint64_t *)(data + 8));
    } else {
        // If not enough data, set default values
        range_start = 0;
        range_end = 0;
    }

    // Ensure range_end is greater than or equal to range_start
    if (range_end < range_start) {
        range_end = range_start;
    }

    // Call the function-under-test
    roaring_bitmap_t *flipped_bitmap = roaring_bitmap_flip(bitmap, range_start, range_end);

    // Clean up
    roaring_bitmap_free(bitmap);
    roaring_bitmap_free(flipped_bitmap);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
