#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to create a valid array of uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Initialize an array of uint32_t from the input data
    size_t num_elements = size / sizeof(uint32_t);
    uint32_t *elements = (uint32_t *)malloc(num_elements * sizeof(uint32_t));
    if (elements == NULL) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Copy data into the elements array
    for (size_t i = 0; i < num_elements; i++) {
        elements[i] = ((const uint32_t *)data)[i];
    }

    // Call the function-under-test
    roaring_bitmap_remove_many(bitmap, num_elements, elements);

    // Clean up
    free(elements);
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

    LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
