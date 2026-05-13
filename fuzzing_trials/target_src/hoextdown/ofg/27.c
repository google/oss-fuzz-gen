#include <stdint.h>
#include <stddef.h>
// #include "/src/hoextdown/src/escape.c" // Include the actual file where hoedown_escape_html is implemented
#include "/src/hoextdown/src/buffer.h" // Include the buffer header for hoedown_buffer functions

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Initialize a hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(64); // Allocate an initial buffer size of 64

    // Ensure the buffer is not NULL
    if (buffer == NULL) {
        return 0;
    }

    // Define a non-zero integer for the flag parameter
    int flag = 1;

    // Call the function-under-test
    hoedown_escape_html(buffer, data, size, flag);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
