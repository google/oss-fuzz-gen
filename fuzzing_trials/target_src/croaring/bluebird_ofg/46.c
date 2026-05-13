#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    uint64_t rank;

    // Ensure size is sufficient to read at least one uint64_t value
    if (size >= sizeof(uint64_t)) {
        // Populate the bitmap with values from the input data
        for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
            uint64_t value = ((const uint64_t *)data)[i];
            roaring64_bitmap_add(bitmap, value);
        }

        // Extract a uint64_t value from the input data to use for rank calculation
        uint64_t value_for_rank = ((const uint64_t *)data)[0];

        // Call the function-under-test
        rank = roaring64_bitmap_rank(bitmap, value_for_rank);
    }

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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
