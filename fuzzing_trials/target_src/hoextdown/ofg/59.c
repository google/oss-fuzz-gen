#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer and related functions

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    hoedown_buffer *buffer;
    unsigned int codepoint;

    // Initialize the buffer
    buffer = hoedown_buffer_new(64); // Assuming 64 as an initial size

    // Ensure the size is sufficient to read an unsigned int from data
    if (size < sizeof(unsigned int)) {
        hoedown_buffer_free(buffer);
        return 0;
    }

    // Extract an unsigned int from the input data
    codepoint = *((unsigned int *)data);

    // Call the function under test
    hoedown_buffer_put_utf8(buffer, codepoint);

    // Clean up
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
