#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t instance
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0; // If creation fails, exit early
    }

    // Ensure that the size is at least the size of a uint64_t
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Interpret the first 8 bytes of data as a uint64_t value
    uint64_t value = *((const uint64_t *)data);

    // Call the function under test
    bool result = roaring64_bitmap_remove_checked(bitmap, value);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
