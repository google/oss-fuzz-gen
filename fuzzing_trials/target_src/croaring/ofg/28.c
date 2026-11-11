#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring64.h" // Correct path for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t structure
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Ensure size is sufficient to extract two uint64_t values
    if (size < sizeof(uint64_t) * 2) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Extract two uint64_t values from data
    uint64_t start = *((const uint64_t *)data);
    uint64_t end = *((const uint64_t *)(data + sizeof(uint64_t)));

    // Call the function-under-test
    bool result = roaring64_bitmap_intersect_with_range(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
