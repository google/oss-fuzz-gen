#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <roaring/roaring.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t structures
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure the bitmaps are not NULL
    if (bitmap1 == NULL || bitmap2 == NULL) {
        if (bitmap1 != NULL) roaring64_bitmap_free(bitmap1);
        if (bitmap2 != NULL) roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Populate the bitmaps with data
    // For simplicity, we'll use the data to add elements to the bitmaps
    for (size_t i = 0; i < size; i++) {
        // Add elements to both bitmaps
        roaring64_bitmap_add(bitmap1, data[i]);
        roaring64_bitmap_add(bitmap2, data[size - i - 1]);
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_intersect(bitmap1, bitmap2);

    // Free the bitmaps
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
