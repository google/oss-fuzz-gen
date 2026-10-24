#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer definitions

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    hoedown_buffer *buffer;

    // Allocate a hoedown_buffer with some initial size
    buffer = hoedown_buffer_new(size > 0 ? size : 1);

    // Ensure that the buffer is not NULL
    if (buffer == NULL) {
        return 0;
    }

    // Fill the buffer with input data if size is greater than 0
    if (size > 0) {
        hoedown_buffer_put(buffer, data, size);
    }

    // Call the function under test
    hoedown_buffer_free(buffer);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
