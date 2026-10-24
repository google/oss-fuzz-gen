#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some values to the bitmap to ensure it's not empty
    for (size_t i = 0; i < size; i++) {
        roaring64_bitmap_add(bitmap, (uint64_t)data[i]);
    }

    // Use a value from the data as the rank index
    uint64_t rank_index = size > 0 ? (uint64_t)data[0] : 0;

    // Call the function-under-test
    uint64_t rank = roaring64_bitmap_rank(bitmap, rank_index);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
