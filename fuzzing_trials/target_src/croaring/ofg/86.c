#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t instance
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();

    // Add some elements to the bitmap to ensure it is not empty
    if (size >= sizeof(uint64_t)) {
        uint64_t value1 = *((const uint64_t *)data);
        roaring64_bitmap_add(bitmap, value1);

        if (size >= 2 * sizeof(uint64_t)) {
            uint64_t value2 = *((const uint64_t *)(data + sizeof(uint64_t)));
            roaring64_bitmap_add(bitmap, value2);
        }
    }

    // Define start and end for the range
    uint64_t start = 0;
    uint64_t end = 100; // Arbitrary end value

    // Call the function-under-test
    uint64_t cardinality = roaring64_bitmap_range_cardinality(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
