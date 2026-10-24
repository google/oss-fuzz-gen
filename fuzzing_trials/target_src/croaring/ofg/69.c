#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>
#include "/src/croaring/include/roaring/roaring.h"

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Initialize a roaring_bitmap_t
    roaring_bitmap_t *bitmap32 = roaring_bitmap_create();
    if (bitmap32 == NULL) {
        return 0;
    }

    // Add some data to the bitmap32, ensuring it's not empty
    for (size_t i = 0; i < size && i < 100; ++i) {
        roaring_bitmap_add(bitmap32, (uint32_t)data[i]);
    }

    // Call the function-under-test
    roaring64_bitmap_t *bitmap64 = roaring64_bitmap_move_from_roaring32(bitmap32);

    // Clean up
    if (bitmap64 != NULL) {
        roaring64_bitmap_free(bitmap64);
    }
    roaring_bitmap_free(bitmap32);

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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
