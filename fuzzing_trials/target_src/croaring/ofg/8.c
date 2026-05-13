#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Initialize the bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Add some values to the bitmap to ensure it's not empty
    for (size_t i = 0; i < size && i < 100; ++i) {
        roaring64_bitmap_add(bitmap, (uint64_t)data[i]);
    }

    // Define the start and end range for flipping
    uint64_t start = 0;
    uint64_t end = size > 1 ? (uint64_t)data[1] : 100; // Ensure end is greater than start

    // Call the function under test
    roaring64_bitmap_t *flipped_bitmap = roaring64_bitmap_flip(bitmap, start, end);

    // Clean up
    if (flipped_bitmap) {
        roaring64_bitmap_free(flipped_bitmap);
    }
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
