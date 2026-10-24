#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> // Include for memcpy
#include "/src/croaring/include/roaring/roaring.h" // Correct path for roaring.h
#include "/src/croaring/include/roaring/bitset_util.h" // Include for bitset_t and related functions

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t)) {
        return 0; // Not enough data to create a bitmap
    }

    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Failed to create bitmap
    }

    // Add values to the bitmap from the input data
    for (size_t i = 0; i < size / sizeof(uint32_t); i++) {
        uint32_t value;
        memcpy(&value, data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }

    // Initialize a bitset
    bitset_t *bitset = bitset_create();
    if (bitset == NULL) {
        roaring_bitmap_free(bitmap);
        return 0; // Failed to create bitset
    }

    // Call the function-under-test
    bool result = roaring_bitmap_to_bitset(bitmap, bitset);

    // Clean up
    roaring_bitmap_free(bitmap);
    bitset_free(bitset);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
