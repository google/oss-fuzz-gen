#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h> // Include for memcpy
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // If creation fails, return early
    }

    // Populate the bitmap with some values from the input data
    // Assuming each uint64_t value is 8 bytes
    for (size_t i = 0; i + sizeof(uint64_t) <= size; i += sizeof(uint64_t)) {
        uint64_t value;
        memcpy(&value, data + i, sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Call the function-under-test
    roaring64_bitmap_remove_run_compression(bitmap);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
