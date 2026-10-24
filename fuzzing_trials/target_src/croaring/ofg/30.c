#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Populate the bitmap with some values from the input data
    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Define start and end for the range
    uint64_t start = 0;
    uint64_t end = size > 0 ? data[0] : 1; // Ensure end is not zero

    // Call the function-under-test
    uint64_t cardinality = roaring_bitmap_range_cardinality(bitmap, start, end);

    // Clean up
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
