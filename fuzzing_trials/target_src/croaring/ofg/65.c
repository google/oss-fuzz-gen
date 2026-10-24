#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t structures
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure the size is sufficient to add elements
    if (size >= 16) {
        // Add elements to the first bitmap
        uint64_t element1 = *((uint64_t*)data);
        roaring64_bitmap_add(bitmap1, element1);

        // Add elements to the second bitmap
        uint64_t element2 = *((uint64_t*)(data + 8));
        roaring64_bitmap_add(bitmap2, element2);

        // Call the function-under-test
        roaring64_bitmap_t *result = roaring64_bitmap_andnot(bitmap1, bitmap2);

        // Free the result bitmap
        roaring64_bitmap_free(result);
    }

    // Free the initialized bitmaps
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
