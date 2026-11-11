#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize the bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL || size < 16) {
        return 0; // Not enough data to proceed
    }

    // Use the first 8 bytes of data as the start index
    uint64_t start_index = *((uint64_t *)data);
    // Use the next 8 bytes of data as the end index
    uint64_t end_index = *((uint64_t *)(data + 8));

    // Ensure start_index is less than or equal to end_index
    if (start_index > end_index) {
        uint64_t temp = start_index;
        start_index = end_index;
        end_index = temp;
    }

    // Call the function-under-test
    roaring64_bitmap_t *flipped_bitmap = roaring64_bitmap_flip(bitmap, start_index, end_index);

    // Cleanup
    roaring64_bitmap_free(flipped_bitmap);
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
