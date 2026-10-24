#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
// #include "/src/hoextdown/src/autolink.c"  // Correct path for the function declaration
#include "/src/hoextdown/src/buffer.h"    // Include for hoedown_buffer related functions

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to provide meaningful input
    if (size < 3) return 0;

    // Initialize the parameters
    size_t link_end = 0;
    hoedown_buffer *buffer = hoedown_buffer_new(size);
    uint8_t *data_copy = (uint8_t *)malloc(size);
    if (data_copy == NULL) return 0;
    memcpy(data_copy, data, size);

    // Extract values for the size_t parameters
    size_t pos = data[0] % size;
    size_t max_rewind = data[1] % size;

    // Extract a value for the unsigned int parameter
    unsigned int flags = data[2];

    // Call the function-under-test
    hoedown_autolink__email(&link_end, buffer, data_copy, pos, max_rewind, flags);

    // Clean up
    hoedown_buffer_free(buffer);
    free(data_copy);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
