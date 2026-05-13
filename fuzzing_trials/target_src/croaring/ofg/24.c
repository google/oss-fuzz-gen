#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    
    if (bitmap == NULL) {
        return 0;
    }

    // Insert some values into the bitmap based on the input data
    for (size_t i = 0; i < size; i += sizeof(uint64_t)) {
        if (i + sizeof(uint64_t) <= size) {
            uint64_t value;
            memcpy(&value, data + i, sizeof(uint64_t));
            roaring64_bitmap_add(bitmap, value);
        }
    }

    // Call the function-under-test
    uint64_t max_value = roaring64_bitmap_maximum(bitmap);

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
