#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/croaring/include/roaring/roaring64.h" // Correct header file for the function

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t) * 2) {
        return 0; // Not enough data to extract two uint64_t values
    }

    // Extract two uint64_t values from the input data
    uint64_t start = *((const uint64_t*)data);
    uint64_t end = *((const uint64_t*)(data + sizeof(uint64_t)));

    // Initialize a roaring64_bitmap_t object
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // Failed to create bitmap
    }

    // Call the function-under-test
    roaring64_bitmap_add_range_closed(bitmap, start, end);

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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
