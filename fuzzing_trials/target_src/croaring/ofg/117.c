#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    roaring_bitmap_t *bitmap;
    size_t range_start, range_length;
    uint32_t *output_array;

    // Ensure the size is sufficient to initialize the parameters
    if (size < sizeof(size_t) * 2) {
        return 0;
    }

    // Initialize the parameters
    bitmap = roaring_bitmap_create();
    range_start = *(size_t *)data;
    range_length = *((size_t *)data + 1);

    // Allocate memory for the output array
    output_array = (uint32_t *)malloc(range_length * sizeof(uint32_t));
    if (output_array == NULL) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Call the function-under-test
    bool result = roaring_bitmap_range_uint32_array(bitmap, range_start, range_length, output_array);

    // Clean up
    free(output_array);
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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
