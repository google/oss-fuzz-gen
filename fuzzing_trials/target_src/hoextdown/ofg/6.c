#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/escape.c"  // Include the correct file for hoedown_escape_href
#include "/src/hoextdown/src/buffer.h"  // Include the necessary header for hoedown_buffer

// Remove 'extern "C"' as this is a C file, not a C++ file
int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Allocate a hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(64);

    // Ensure the buffer is not NULL
    if (buffer == NULL) {
        return 0;
    }

    // Call the function-under-test
    hoedown_escape_href(buffer, data, size);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
