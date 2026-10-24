#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring.h"

int LLVMFuzzerTestOneInput_169(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    uint32_t value = 0;

    // Ensure size is sufficient to extract a uint32_t value
    if (size >= sizeof(uint32_t)) {
        // Extract a uint32_t value from the data
        value = *(const uint32_t *)data;
    }

    // Initialize the bulk context
    roaring_bulk_context_t bulk_context = {0}; // Initialize the bulk context directly

    // Call the function under test
    bool result = roaring_bitmap_contains_bulk(bitmap, &bulk_context, value);

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

    LLVMFuzzerTestOneInput_169(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
