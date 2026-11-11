#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy function
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer and hoedown_buffer_uninit

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    hoedown_buffer *buf = NULL;

    // Allocate memory for hoedown_buffer
    buf = (hoedown_buffer*) malloc(sizeof(hoedown_buffer));
    if (buf == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize the buffer with non-NULL values
    buf->data = (uint8_t*) malloc(size);
    if (buf->data == NULL) {
        free(buf);
        return 0; // Exit if memory allocation fails
    }

    buf->size = size;
    buf->asize = size;
    buf->unit = 1; // Set a non-zero unit size

    // Copy data into the buffer
    if (size > 0) {
        memcpy(buf->data, data, size);
    }

    // Call the function-under-test
    hoedown_buffer_uninit(buf);

    // Free the allocated memory
    free(buf->data);
    free(buf);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
