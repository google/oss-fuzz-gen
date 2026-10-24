#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

#ifdef __cplusplus
extern "C" {
#endif

// Function signature to be fuzzed
uint64_t roaring64_bitmap_and_cardinality(const roaring64_bitmap_t *, const roaring64_bitmap_t *);

// Fuzzing harness
int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Declare and initialize the roaring64_bitmap_t pointers
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    // Ensure that data is not empty
    if (size > 0) {
        // Use the data to add values to the bitmaps
        for (size_t i = 0; i < size; i++) {
            roaring64_bitmap_add(bitmap1, data[i]);
            roaring64_bitmap_add(bitmap2, data[size - i - 1]);  // Reverse order for variety
        }
    }

    // Call the function-under-test
    uint64_t result = roaring64_bitmap_and_cardinality(bitmap1, bitmap2);

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
