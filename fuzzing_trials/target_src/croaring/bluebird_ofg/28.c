#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "roaring/roaring64.h"

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Initialize two roaring64_bitmap_t instances
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        return 0;
    }

    // Add some elements to the bitmaps to ensure they are not empty
    for (size_t i = 0; i < size; i++) {
        roaring64_bitmap_add(bitmap1, data[i]);
        roaring64_bitmap_add(bitmap2, data[size - i - 1]);
    }

    // Call the function-under-test
    roaring64_bitmap_t *result = roaring64_bitmap_and(bitmap1, bitmap2);

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
