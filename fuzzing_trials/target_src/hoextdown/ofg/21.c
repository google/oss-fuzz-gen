#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h"

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize a hoedown_buffer
    size_t buffer_size = 64; // Arbitrary buffer size
    hoedown_buffer *buffer = hoedown_buffer_new(buffer_size);

    // Use the first byte of data as the character to put in the buffer
    uint8_t character = data[0];

    // Call the function-under-test
    hoedown_buffer_putc(buffer, character);

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
