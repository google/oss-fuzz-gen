#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring.h" // Correct path for the header file

int LLVMFuzzerTestOneInput_130(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0; // Exit if memory allocation fails
    }

    // Ensure we have enough data for at least one uint64_t value
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Calculate the number of uint64_t elements we can extract from the data
    size_t num_elements = size / sizeof(uint64_t);

    // Allocate memory for the uint64_t array
    uint64_t *elements = (uint64_t *)malloc(num_elements * sizeof(uint64_t));
    if (!elements) {
        roaring64_bitmap_free(bitmap);
        return 0; // Exit if memory allocation fails
    }

    // Copy the data into the uint64_t array
    for (size_t i = 0; i < num_elements; ++i) {
        elements[i] = ((uint64_t *)data)[i];
    }

    // Call the function under test
    roaring64_bitmap_remove_many(bitmap, num_elements, elements);

    // Clean up
    free(elements);
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

    LLVMFuzzerTestOneInput_130(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
