#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();

    // Add some data to the bitmap if size is sufficient
    if (size > 0) {
        uint64_t value = 0;
        for (size_t i = 0; i < size; ++i) {
            value = (value << 8) | data[i];
            roaring64_bitmap_add(bitmap, value);
        }
    }

    // Allocate a buffer to serialize into
    size_t buffer_size = roaring64_bitmap_frozen_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);

    // Call the function-under-test
    size_t serialized_size = roaring64_bitmap_frozen_serialize(bitmap, buffer);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
