#include <stdint.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring.h"  // Include the appropriate header for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    roaring64_bitmap_t *bitmap;
    uint64_t start_range;
    uint64_t end_range;

    // Initialize the bitmap
    bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // If bitmap creation fails, exit early
    }

    // Ensure size is large enough to extract two uint64_t values
    if (size < 16) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Extract start and end range from the input data
    start_range = *((const uint64_t *)data);
    end_range = *((const uint64_t *)(data + 8));

    // Call the function-under-test
    roaring64_bitmap_remove_range(bitmap, start_range, end_range);

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

    LLVMFuzzerTestOneInput_161(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
