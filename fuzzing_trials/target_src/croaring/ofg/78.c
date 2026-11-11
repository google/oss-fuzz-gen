#include <stdint.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring64.h" // Correct include for 64-bit roaring bitmap

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Ensure the bitmap is not empty by adding some elements
    for (size_t i = 0; i < size; ++i) {
        uint64_t value = (uint64_t)data[i];
        roaring64_bitmap_add(bitmap, value);
    }

    // Call the function-under-test
    size_t new_size = roaring64_bitmap_shrink_to_fit(bitmap);

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
