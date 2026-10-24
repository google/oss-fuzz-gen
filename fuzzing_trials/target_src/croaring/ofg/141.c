#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring64.h"  // Correct path for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Return if the bitmap creation failed
    }

    // Ensure there's enough data to read a uint64_t value
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Read the uint64_t value from the input data
    uint64_t value = *((const uint64_t *)data);

    // Call the function-under-test
    bool result = roaring64_bitmap_add_checked(bitmap, value);

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

    LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
