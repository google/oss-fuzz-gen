#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t objects
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure the bitmaps are not NULL
    if (bitmap1 == NULL || bitmap2 == NULL) {
        return 0;
    }

    // Populate the bitmaps with data
    // We use the input data to add values to the bitmaps
    for (size_t i = 0; i < size; i += sizeof(uint64_t)) {
        uint64_t value = 0;
        if (i + sizeof(uint64_t) <= size) {
            value = *((uint64_t *)(data + i));
        }
        roaring64_bitmap_add(bitmap1, value);
        roaring64_bitmap_add(bitmap2, value + 1); // Add a different value to bitmap2
    }

    // Call the function-under-test
    roaring64_bitmap_t *result_bitmap = roaring64_bitmap_or(bitmap1, bitmap2);

    // Clean up
    if (result_bitmap != NULL) {
        roaring64_bitmap_free(result_bitmap);
    }
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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
