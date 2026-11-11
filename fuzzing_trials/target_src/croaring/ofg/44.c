#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring.h"  // Correct path for the header file

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read at least one uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a roaring bitmap from the input data
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Insert values into the bitmap from the input data
    for (size_t i = 0; i < size / sizeof(uint32_t); i++) {
        uint32_t value = ((uint32_t *)data)[i];
        roaring_bitmap_add(bitmap, value);
    }

    // Initialize a roaring_uint32_iterator_t
    roaring_uint32_iterator_t *iterator = roaring_create_iterator(bitmap);

    // Allocate memory for the output uint32_t
    uint32_t *output_value = (uint32_t *)malloc(sizeof(uint32_t));
    if (output_value == NULL) {
        roaring_free_uint32_iterator(iterator);
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Extract a uint32_t from the input data for the third parameter
    uint32_t max_value = *((uint32_t *)data);

    // Call the function-under-test
    roaring_uint32_iterator_read(iterator, output_value, max_value);

    // Clean up
    free(output_value);
    roaring_free_uint32_iterator(iterator);
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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
