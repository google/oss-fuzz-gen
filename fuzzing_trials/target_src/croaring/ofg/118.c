#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <roaring/roaring.h>
#include <stdlib.h>

// Remove the `extern "C"` linkage specification since this is C code, not C++.
int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Add some data to the bitmap to ensure it's not empty
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Define the range and array to store the results
    size_t offset = 0;
    size_t range_size = size < 10 ? size : 10;  // Limit range size for simplicity
    uint32_t *array = (uint32_t *)malloc(range_size * sizeof(uint32_t));
    if (!array) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Call the function-under-test
    bool result = roaring_bitmap_range_uint32_array(bitmap, offset, range_size, array);

    // Clean up
    free(array);
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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
