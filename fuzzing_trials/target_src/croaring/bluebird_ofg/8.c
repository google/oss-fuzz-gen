#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    // Call the function-under-test with the provided data and size
    roaring_bitmap_t *bitmap = roaring_bitmap_deserialize_safe((const void *)data, size);

    // Check if the bitmap was successfully created
    if (bitmap != NULL) {
        // Perform operations on the bitmap if necessary
        // Example: check the number of elements in the bitmap
        uint64_t cardinality = roaring_bitmap_get_cardinality(bitmap);

        // Free the bitmap after use
        roaring_bitmap_free(bitmap);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
