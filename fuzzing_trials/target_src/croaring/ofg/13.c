#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    uint64_t start = 0;
    uint64_t end = 0;

    // Ensure size is sufficient to extract two 64-bit integers
    if (size >= 16) {
        // Extract start and end values from input data
        start = *((const uint64_t *)data);
        end = *((const uint64_t *)(data + 8));
    }

    // Call the function under test
    roaring64_bitmap_add_range_closed(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
