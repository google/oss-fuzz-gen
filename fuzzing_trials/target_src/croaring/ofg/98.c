#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap to ensure it's not empty
    for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Allocate a buffer for serialization
    size_t buffer_size = roaring64_bitmap_portable_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);
    if (buffer == NULL) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Serialize the bitmap
    roaring64_bitmap_portable_serialize(bitmap, buffer);

    // Clean up
    free(buffer);
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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
