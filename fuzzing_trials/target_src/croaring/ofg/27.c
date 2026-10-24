#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract two uint64_t values
    if (size < sizeof(uint64_t) * 2) {
        return 0;
    }

    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Extract two uint64_t values from the input data
    uint64_t range_start = *(const uint64_t *)(data);
    uint64_t range_end = *(const uint64_t *)(data + sizeof(uint64_t));

    // Ensure range_end is greater than or equal to range_start
    if (range_end < range_start) {
        uint64_t temp = range_start;
        range_start = range_end;
        range_end = temp;
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_intersect_with_range(bitmap, range_start, range_end);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
