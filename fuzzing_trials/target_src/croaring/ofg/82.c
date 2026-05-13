#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Add data to the bitmap if size is appropriate
    if (size >= sizeof(uint32_t)) {
        // Interpret the input data as an array of uint32_t
        const uint32_t *input_data = (const uint32_t *)data;
        size_t num_elements = size / sizeof(uint32_t);

        // Add elements to the bitmap
        for (size_t i = 0; i < num_elements; i++) {
            roaring_bitmap_add(bitmap, input_data[i]);
        }
    }

    // Initialize statistics structure
    roaring_statistics_t stats;

    // Call the function-under-test
    roaring_bitmap_statistics(bitmap, &stats);

    // Free the bitmap
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
