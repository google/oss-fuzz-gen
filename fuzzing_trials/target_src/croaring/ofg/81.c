#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Initialize the bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    // Add data to the bitmap
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Initialize the statistics structure
    roaring_statistics_t stats;

    // Call the function-under-test
    roaring_bitmap_statistics(bitmap, &stats);

    // Free the bitmap
    roaring_bitmap_free(bitmap);

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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
