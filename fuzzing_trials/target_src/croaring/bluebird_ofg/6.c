#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "roaring/roaring.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    char *output_buffer = NULL;

    if (bitmap == NULL) {
        return 0;
    }

    // Ensure the input data is not empty
    if (size > 0) {
        // Add some elements to the bitmap using the input data
        for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
            uint64_t value;
            memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
            roaring64_bitmap_add(bitmap, value);
        }

        // Allocate memory for the output buffer
        size_t serialized_size = roaring64_bitmap_portable_size_in_bytes(bitmap);
        output_buffer = (char *)malloc(serialized_size);

        if (output_buffer != NULL) {
            // Call the function-under-test
            roaring64_bitmap_portable_serialize(bitmap, output_buffer);

            // Free the output buffer after use
            free(output_buffer);
        }
    }

    // Free the bitmap
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
