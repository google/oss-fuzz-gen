#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for our needs
    if (size < sizeof(uint32_t) * 3) {
        return 0;
    }

    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Add some values to the bitmap
    for (size_t i = 0; i < size / sizeof(uint32_t); ++i) {
        roaring_bitmap_add(bitmap, ((uint32_t *)data)[i]);
    }

    // Initialize the iterator
    roaring_uint32_iterator_t *iterator = roaring_create_iterator(bitmap);

    // Prepare the uint32_t array
    uint32_t values[3];
    for (size_t i = 0; i < 3; ++i) {
        values[i] = ((uint32_t *)data)[i];
    }

    // Call the function-under-test
    uint32_t result = roaring_uint32_iterator_read(iterator, values, 3);

    // Clean up
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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
