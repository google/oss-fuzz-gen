#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    if (size < 16) {
        return 0;
    }

    // Initialize the roaring64_bitmap_t object
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Extract two uint64_t values from the input data
    uint64_t start = *((uint64_t *)data);
    uint64_t end = *((uint64_t *)(data + 8));

    // Ensure that start is less than or equal to end
    if (start > end) {
        uint64_t temp = start;
        start = end;
        end = temp;
    }

    // Call the function-under-test
    roaring64_bitmap_flip_inplace(bitmap, start, end);

    // Free the bitmap to avoid memory leaks
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

    LLVMFuzzerTestOneInput_165(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
