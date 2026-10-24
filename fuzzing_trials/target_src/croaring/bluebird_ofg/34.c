#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t) * 2 + sizeof(uint32_t)) {
        return 0; // Not enough data to extract three parameters
    }

    // Extract parameters from the input data
    uint64_t start = *((uint64_t *)data);
    uint64_t end = *((uint64_t *)(data + sizeof(uint64_t)));
    uint32_t step = *((uint32_t *)(data + sizeof(uint64_t) * 2));

    // Call the function-under-test
    roaring_bitmap_t *bitmap = roaring_bitmap_from_range(start, end, step);

    // Clean up
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
