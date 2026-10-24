#include <stdint.h>
#include <stddef.h>
#include <roaring/roaring.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Initialize a new roaring64_bitmap_t
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();

    if (bitmap == NULL) {
        return 0; // Return if the bitmap creation failed
    }

    // Insert some data into the bitmap to ensure it's not empty
    // We use the data provided by the fuzzer
    for (size_t i = 0; i < size; i++) {
        roaring64_bitmap_add(bitmap, data[i]);
    }

    // Call the function-under-test
    size_t frozen_size = roaring64_bitmap_frozen_size_in_bytes(bitmap);

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

    LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
