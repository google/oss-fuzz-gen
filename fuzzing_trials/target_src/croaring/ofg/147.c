#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Insert some values into the bitmap for testing
    // Ensure that the bitmap is not empty
    roaring64_bitmap_add(bitmap, 1);
    roaring64_bitmap_add(bitmap, 2);
    roaring64_bitmap_add(bitmap, 3);

    // Use the data to generate start and end values
    uint64_t start = 0;
    uint64_t end = 0;
    if (size >= sizeof(uint64_t)) {
        start = *((const uint64_t *)data);
        if (size >= 2 * sizeof(uint64_t)) {
            end = *((const uint64_t *)(data + sizeof(uint64_t)));
        }
    }

    // Call the function-under-test
    roaring64_bitmap_t *flipped_bitmap = roaring64_bitmap_flip_closed(bitmap, start, end);

    // Clean up
    if (flipped_bitmap != NULL) {
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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
