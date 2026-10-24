#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Initialize the bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Exit if bitmap creation fails
    }

    // Ensure that there is enough data to extract two uint64_t values
    if (size < sizeof(uint64_t) * 2) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Extract two uint64_t values from the input data
    uint64_t start = *((const uint64_t *)data);
    uint64_t end = *((const uint64_t *)(data + sizeof(uint64_t)));

    // Call the function-under-test
    roaring64_bitmap_add_range(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
