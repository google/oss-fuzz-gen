#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    uint32_t value = 0;

    // Ensure there is enough data to work with
    if (size < sizeof(uint32_t)) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Extract a uint32_t value from the input data
    value = *((uint32_t *)data);

    // Call the function-under-test
    roaring_bitmap_add(bitmap, value);

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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
