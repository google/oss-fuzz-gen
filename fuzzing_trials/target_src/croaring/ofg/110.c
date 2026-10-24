#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Initialize variables
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    bool flag = true; // Arbitrarily set to true, can be varied
    uint64_t offset = 0;

    // Ensure size is sufficient to extract a 64-bit offset
    if (size >= sizeof(uint64_t)) {
        // Use the first 8 bytes of data as the offset
        offset = *((uint64_t*)data);
    }

    // Call the function-under-test
    roaring64_bitmap_t *result = roaring64_bitmap_add_offset_signed(bitmap, flag, offset);

    // Clean up
    roaring64_bitmap_free(bitmap);
    roaring64_bitmap_free(result);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
