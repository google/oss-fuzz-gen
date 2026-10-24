#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    // Initialize the roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0; // If creation fails, exit early
    }

    // Ensure there is enough data to create at least one uint64_t element
    if (size < sizeof(uint64_t)) {
        roaring64_bitmap_free(bitmap);
        return 0;
    }

    // Calculate the number of uint64_t elements we can extract from the input data
    size_t num_elements = size / sizeof(uint64_t);

    // Cast the input data to a uint64_t array
    const uint64_t *elements = (const uint64_t *)data;

    // Call the function-under-test
    roaring64_bitmap_add_many(bitmap, num_elements, elements);

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

    LLVMFuzzerTestOneInput_104(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
