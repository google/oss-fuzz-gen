#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring64.h"  // Correct path for the roaring64_bitmap_t structure

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // If creation fails, return early
    }

    // Add some values to the bitmap for testing purposes
    roaring64_bitmap_add(bitmap, 1);
    roaring64_bitmap_add(bitmap, 2);
    roaring64_bitmap_add(bitmap, 3);

    // Use the data to determine the rank value
    uint64_t rank = 0;
    if (size >= sizeof(uint64_t)) {
        rank = *((const uint64_t *)data); // Use the input data to set the rank
    }

    uint64_t element = 0; // Initialize the element to store the result

    // Call the function-under-test
    bool result = roaring64_bitmap_select(bitmap, rank, &element);

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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
