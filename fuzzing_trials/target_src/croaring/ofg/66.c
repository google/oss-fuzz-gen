#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    
    // Ensure the bitmap is not NULL
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap for testing purposes
    // Here we simply add a few numbers for demonstration
    roaring64_bitmap_add(bitmap, 1);
    roaring64_bitmap_add(bitmap, 2);
    roaring64_bitmap_add(bitmap, 3);
    
    // Define start and end for the range
    uint64_t start = 0;
    uint64_t end = 2;

    // Call the function-under-test
    uint64_t cardinality = roaring64_bitmap_range_closed_cardinality(bitmap, start, end);

    // Cleanup
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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
