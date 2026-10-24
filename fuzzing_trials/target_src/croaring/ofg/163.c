#include <stdint.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    // Initialize a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap for testing
    for (uint32_t i = 0; i < size && i < 1000; ++i) {
        roaring_bitmap_add(bitmap, i);
    }

    // Prepare the input arrays for the function
    uint32_t n = size / sizeof(uint32_t);
    uint32_t *ranks = (uint32_t *)malloc(n * sizeof(uint32_t));
    uint32_t *values = (uint32_t *)malloc(n * sizeof(uint32_t));
    uint64_t *answers = (uint64_t *)malloc(n * sizeof(uint64_t));

    if (ranks == NULL || values == NULL || answers == NULL) {
        free(ranks);
        free(values);
        free(answers);
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Initialize ranks and values with data
    for (uint32_t i = 0; i < n; ++i) {
        ranks[i] = i;
        values[i] = i;
    }

    // Call the function-under-test
    roaring_bitmap_rank_many(bitmap, ranks, values, answers);

    // Free allocated resources
    free(ranks);
    free(values);
    free(answers);
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

    LLVMFuzzerTestOneInput_163(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
