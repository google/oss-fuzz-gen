#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Exit if bitmap creation fails
    }

    // Ensure size is a multiple of 4 for uint32_t array
    if (size < sizeof(uint32_t)) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Calculate the number of elements for the uint32_t array
    size_t num_elements = size / sizeof(uint32_t);

    // Cast the data to uint32_t array
    const uint32_t *elements = (const uint32_t *)data;

    // Add some elements to the bitmap to ensure it is not empty
    for (size_t i = 0; i < num_elements; i++) {
        roaring_bitmap_add(bitmap, elements[i]);
    }

    // Call the function-under-test
    roaring_bitmap_remove_many(bitmap, num_elements, elements);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
