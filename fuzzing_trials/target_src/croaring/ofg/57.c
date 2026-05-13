#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract at least one uint64_t element
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Calculate the number of uint64_t elements we can extract from the data
    size_t num_elements = size / sizeof(uint64_t);

    // Cast the input data to a uint64_t pointer
    const uint64_t *elements = (const uint64_t *)data;

    // Call the function-under-test
    roaring64_bitmap_t *bitmap = roaring64_bitmap_of_ptr(num_elements, elements);

    // Clean up the created bitmap to avoid memory leaks
    if (bitmap != NULL) {
        roaring64_bitmap_free(bitmap);
    }

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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
