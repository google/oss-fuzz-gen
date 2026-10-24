#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap to ensure it's not empty
    roaring_bitmap_add(bitmap, 1);
    roaring_bitmap_add(bitmap, 2);
    roaring_bitmap_add(bitmap, 3);

    // Ensure the size is at least 4 bytes to read a uint32_t
    if (size < sizeof(uint32_t)) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Use the first 4 bytes of data as the index
    uint32_t index = *((const uint32_t *)data);

    // Call the function-under-test
    int64_t result = roaring_bitmap_get_index(bitmap, index);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
