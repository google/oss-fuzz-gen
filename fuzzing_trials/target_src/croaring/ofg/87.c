#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2) {
        return 0;
    }

    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some values to the bitmap using the input data
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Allocate a buffer for serialization
    size_t buffer_size = roaring_bitmap_frozen_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Call the function-under-test
    roaring_bitmap_frozen_serialize(bitmap, buffer);

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
