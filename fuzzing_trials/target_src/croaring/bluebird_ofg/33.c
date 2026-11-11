#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring/roaring64.h"

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    if (size < sizeof(uint64_t)) {
        return 0; // Not enough data to form a single uint64_t
    }

    // Calculate the number of 64-bit integers we can extract from the input data
    size_t num_elements = size / sizeof(uint64_t);
    const uint64_t *elements = (const uint64_t *)data;

    // Call the function-under-test
    roaring64_bitmap_t *bitmap = roaring64_bitmap_of_ptr(num_elements, elements);

    // Clean up
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
