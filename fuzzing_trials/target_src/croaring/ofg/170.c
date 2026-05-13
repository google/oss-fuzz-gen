#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract at least one element
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Calculate the number of elements we can safely extract
    size_t num_elements = size / sizeof(uint32_t);

    // Cast the data to an array of uint32_t
    const uint32_t *elements = (const uint32_t *)data;

    // Call the function-under-test with the extracted elements
    roaring_bitmap_t *bitmap = roaring_bitmap_of(num_elements, (void *)elements);

    // Clean up the bitmap if it was created
    if (bitmap != NULL) {
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

    LLVMFuzzerTestOneInput_170(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
