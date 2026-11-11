#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to extract two 64-bit integers
    if (size < 2 * sizeof(uint64_t)) {
        return 0;
    }

    // Extract two 64-bit integers from the input data
    uint64_t start = *((const uint64_t *)data);
    uint64_t end = *((const uint64_t *)(data + sizeof(uint64_t)));

    // Create a roaring64 bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Call the function-under-test
    roaring64_bitmap_t *result = roaring64_bitmap_flip_closed(bitmap, start, end);

    // Clean up
    if (result) {
        roaring64_bitmap_free(result);
    }
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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
