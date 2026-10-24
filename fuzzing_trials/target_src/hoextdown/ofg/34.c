#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/buffer.h" // Include the correct header for hoedown_buffer
// #include "/src/hoextdown/src/autolink.c"

// Declare the function prototype if not included in any header
extern size_t hoedown_autolink__www(size_t *, hoedown_buffer *, uint8_t *, size_t, size_t, unsigned int);

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    if (size < 3) return 0; // Ensure there is enough data for minimum input

    size_t link_end = 0;
    hoedown_buffer buffer;
    buffer.data = (uint8_t *)data;
    buffer.size = size;
    buffer.asize = size;
    buffer.unit = 1;

    uint8_t *link_data = (uint8_t *)data;
    size_t offset = 1;
    size_t max_rewind = 1;
    unsigned int flags = 0;

    // Call the function-under-test
    hoedown_autolink__www(&link_end, &buffer, link_data, offset, max_rewind, flags);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
