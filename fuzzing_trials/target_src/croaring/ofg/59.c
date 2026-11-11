#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Initialize the bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();

    // Iterate over the input data in chunks of 8 bytes
    for (size_t i = 0; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        // Use each 8-byte chunk as a uint64_t value
        uint64_t value = *((const uint64_t *)(data + i));

        // Call the function-under-test
        roaring64_bitmap_add(bitmap, value);
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
