#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t) * 2) {
        return 0; // Not enough data to extract two uint32_t values
    }

    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0; // Failed to create a bitmap
    }

    // Add some elements to the bitmap for testing
    for (uint32_t i = 0; i < 100; i++) {
        roaring_bitmap_add(bitmap, i);
    }

    // Extract two uint32_t values from the input data
    uint32_t start = *((uint32_t *)data);
    uint32_t end = *((uint32_t *)(data + sizeof(uint32_t)));

    // Ensure start is less than or equal to end
    if (start > end) {
        uint32_t temp = start;
        start = end;
        end = temp;
    }

    // Call the function-under-test
    uint64_t cardinality = roaring_bitmap_range_cardinality_closed(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_158(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
