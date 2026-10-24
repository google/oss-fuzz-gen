#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0; // If creation fails, exit early
    }

    // Add some data to the bitmap to make it non-empty
    for (size_t i = 0; i < size; ++i) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Define start and end for the flip operation
    uint64_t start = 0;
    uint64_t end = size > 0 ? data[size - 1] : 1; // Ensure end is greater than start

    // Call the function-under-test
    roaring_bitmap_t *flipped_bitmap = roaring_bitmap_flip(bitmap, start, end);

    // Free the original bitmap
    roaring_bitmap_free(bitmap);

    // Free the flipped bitmap if it was created successfully
    if (flipped_bitmap != NULL) {
        roaring_bitmap_free(flipped_bitmap);
    }

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
