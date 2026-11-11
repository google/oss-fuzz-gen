#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t) + sizeof(bool)) {
        return 0;
    }

    // Initialize a roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Use the first part of data to determine the boolean value
    bool offset_sign = (data[0] % 2 == 0);

    // Use the next part of data to determine the offset value
    uint64_t offset = *((uint64_t *)(data + 1));

    // Call the function under test
    roaring64_bitmap_t *result = roaring64_bitmap_add_offset_signed(bitmap, offset_sign, offset);

    // Clean up
    roaring64_bitmap_free(bitmap);
    if (result) {
        roaring64_bitmap_free(result);
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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
