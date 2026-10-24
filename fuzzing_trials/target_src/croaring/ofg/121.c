#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>  // Include the Roaring library header

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    if (size < 24) {
        // We need at least 24 bytes to extract three uint64_t values
        return 0;
    }

    // Extract three uint64_t values from the input data
    uint64_t start = *((const uint64_t *)(data));
    uint64_t end = *((const uint64_t *)(data + 8));
    uint64_t step = *((const uint64_t *)(data + 16));

    // Call the function-under-test
    roaring64_bitmap_t *bitmap = roaring64_bitmap_from_range(start, end, step);

    // Clean up the bitmap if it was created
    if (bitmap != NULL) {
        roaring64_bitmap_free(bitmap);
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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
