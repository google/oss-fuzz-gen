#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring/roaring64.h"  // Correct header file for the function and type definitions

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Return if bitmap creation fails
    }

    // Ensure there is enough data to form a uint64_t value
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Iterate over the input data to add multiple values to the bitmap
    for (size_t offset = 0; offset + sizeof(uint64_t) <= size; offset += sizeof(uint64_t)) {
        // Extract a uint64_t value from the input data
        uint64_t value = 0;
        for (size_t i = 0; i < sizeof(uint64_t); i++) {
            value |= ((uint64_t)data[offset + i]) << (i * 8);
        }

        // Call the function-under-test
        bool result = roaring64_bitmap_add_checked(bitmap, value);

        // Optionally, you can check the result or perform additional operations
        (void)result; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
