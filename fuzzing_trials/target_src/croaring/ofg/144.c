#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/croaring/include/roaring/roaring64.h" // Correct header for roaring64_bitmap_t

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap;
    uint64_t *array;
    size_t array_size;

    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Initialize the bitmap
    bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Insert data into the bitmap
    for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Allocate memory for the array
    array_size = roaring64_bitmap_get_cardinality(bitmap);
    array = (uint64_t *)malloc(array_size * sizeof(uint64_t));
    if (array == NULL) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Call the function-under-test
    roaring64_bitmap_to_uint64_array(bitmap, array);

    // Cleanup
    free(array);
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

    LLVMFuzzerTestOneInput_144(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
