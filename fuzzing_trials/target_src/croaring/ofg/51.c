#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Initialize a roaring_bitmap_t
    roaring_bitmap_t *bitmap = roaring_bitmap_create();

    // Ensure the bitmap is not NULL
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap to ensure it's not empty
    for (size_t i = 0; i < size; ++i) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    // Call the function under test
    roaring_bitmap_repair_after_lazy(bitmap);

    // Free the bitmap after use
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
