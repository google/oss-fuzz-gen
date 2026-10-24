#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Initialize a roaring64_bitmap_t object
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    
    if (bitmap == NULL) {
        return 0; // If creation fails, exit early
    }

    // Add data to the bitmap for fuzzing
    for (size_t i = 0; i < size; i++) {
        roaring64_bitmap_add(bitmap, (uint64_t)data[i]);
    }

    // Call the function-under-test
    bool result = roaring64_bitmap_run_optimize(bitmap);

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

    LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
