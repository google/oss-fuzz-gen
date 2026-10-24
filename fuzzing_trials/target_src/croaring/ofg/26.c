#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>
#include "/src/croaring/include/roaring/containers/run.h"
#include "/src/croaring/include/roaring/memory.h"

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t object
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0; // Return early if bitmap creation fails
    }

    // Ensure the data is not NULL and has a valid size
    if (data == NULL || size == 0) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Use the input data to add values to the bitmap
    for (size_t i = 0; i < size; i++) {
        // Add each byte of the input data as a value in the bitmap
        roaring64_bitmap_add(bitmap, data[i]);
    }

    // Allocate a buffer for serialization
    size_t max_serialized_size = roaring64_bitmap_frozen_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(max_serialized_size);
    if (!buffer) {
        roaring64_bitmap_free(bitmap);
        return 0; // Return early if buffer allocation fails
    }

    // Call the function-under-test
    size_t serialized_size = roaring64_bitmap_frozen_serialize(bitmap, buffer);

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
