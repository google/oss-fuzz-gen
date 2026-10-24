#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    hoedown_buffer buffer;
    buffer.data = (uint8_t *)malloc(size > 0 ? size : 1); // Allocate at least 1 byte to avoid NULL
    buffer.size = size;
    buffer.asize = size;
    buffer.unit = 64; // Arbitrary non-zero value for unit size

    // Ensure that the buffer is not NULL
    if (buffer.data == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test
    hoedown_buffer_grow(&buffer, size);

    // Clean up
    free(buffer.data);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
