#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(uint64_t)) {
        return 0; // Not enough data to create two 64-bit integers
    }

    // Initialize two roaring64_bitmap_t objects
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Use the first 64 bits of the input data to populate bitmap1
    uint64_t value1 = *((const uint64_t *)data);
    roaring64_bitmap_add(bitmap1, value1);

    // Use the next 64 bits of the input data to populate bitmap2
    uint64_t value2 = *((const uint64_t *)(data + sizeof(uint64_t)));
    roaring64_bitmap_add(bitmap2, value2);

    // Call the function-under-test
    bool result = roaring64_bitmap_is_strict_subset(bitmap1, bitmap2);

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
