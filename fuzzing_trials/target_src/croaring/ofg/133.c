#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "/src/croaring/include/roaring/roaring64.h"

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        return 0;
    }

    // Allocate memory for the input string
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }

    // Copy the data to the input string and null-terminate it
    memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    roaring64_bitmap_t *bitmap = roaring64_bitmap_frozen_view(input, size);

    // Free the allocated memory
    free(input);

    // Normally, you would want to do something with the bitmap, like checking its validity,
    // but for fuzz testing, we just need to ensure it doesn't crash.
    // If bitmap is not NULL, you may want to release it if the function requires it.
    if (bitmap != NULL) {
        // Assuming there's a function to release the bitmap if needed
        // roaring64_bitmap_free(bitmap);
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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
