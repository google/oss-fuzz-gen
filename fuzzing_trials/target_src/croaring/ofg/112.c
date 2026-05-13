#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Ensure there is enough data to form an int64_t offset
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Create a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Populate the bitmap with some values
    for (size_t i = 0; i < size - sizeof(int64_t); i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Extract the offset from the data
    int64_t offset;
    memcpy(&offset, data + size - sizeof(int64_t), sizeof(int64_t));

    // Call the function-under-test
    roaring_bitmap_t *result = roaring_bitmap_add_offset(bitmap, offset);

    // Clean up
    if (result != bitmap) {
        roaring_bitmap_free(result);
    }
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

    LLVMFuzzerTestOneInput_112(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
