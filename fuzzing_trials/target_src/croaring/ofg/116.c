#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include string.h for memcpy
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    
    // Check if the bitmap was created successfully
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap using the input data
    for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
        uint64_t value;
        // Copy data into value ensuring we don't read out of bounds
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Call the function-under-test
    uint64_t min_value = roaring64_bitmap_minimum(bitmap);

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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
