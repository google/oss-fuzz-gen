#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Initialize the roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Populate the bitmap with some values
    for (size_t i = 0; i < size; ++i) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Create arrays for input and output
    uint32_t num_queries = size > 0 ? size : 1;
    uint32_t *input_values = (uint32_t *)malloc(num_queries * sizeof(uint32_t));
    uint32_t *output_values = (uint32_t *)malloc(num_queries * sizeof(uint32_t));
    uint64_t *rank_results = (uint64_t *)malloc(num_queries * sizeof(uint64_t));

    if (input_values == NULL || output_values == NULL || rank_results == NULL) {
        roaring_bitmap_free(bitmap);
        free(input_values);
        free(output_values);
        free(rank_results);
        return 0;
    }

    // Initialize input and output arrays
    for (uint32_t i = 0; i < num_queries; ++i) {
        input_values[i] = i;
        output_values[i] = i;
    }

    // Call the function-under-test
    roaring_bitmap_rank_many(bitmap, input_values, output_values, rank_results);

    // Clean up
    roaring_bitmap_free(bitmap);
    free(input_values);
    free(output_values);
    free(rank_results);

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

    LLVMFuzzerTestOneInput_164(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
