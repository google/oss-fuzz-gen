#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy function
#include "/src/hoextdown/src/autolink.c" // Correct path for the function declaration

// Function signature
size_t hoedown_autolink__url(size_t *rewind_p, hoedown_buffer *link, uint8_t *data, size_t offset, size_t size, unsigned int flags);

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Ensure size is large enough to avoid out-of-bounds access
    if (size < 1) return 0;

    // Initialize the parameters for the function
    size_t rewind = 0;
    hoedown_buffer link;
    link.data = (uint8_t *)malloc(size);
    link.size = size;
    link.asize = size;
    link.unit = 1;

    // Copy the input data to the link buffer
    if (link.data != NULL) {
        memcpy(link.data, data, size);
    }

    uint8_t *data_copy = (uint8_t *)malloc(size);
    if (data_copy != NULL) {
        memcpy(data_copy, data, size);
    }

    size_t offset = 0;
    unsigned int flags = 0;

    // Call the function-under-test
    hoedown_autolink__url(&rewind, &link, data_copy, offset, size, flags);

    // Free allocated memory
    free(link.data);
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
