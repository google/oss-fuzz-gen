#include <stddef.h>
#include <stdint.h>
#include "/src/hoextdown/src/buffer.h"

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure that the size is non-zero and use it as the parameter for hoedown_buffer_new
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    hoedown_buffer *buffer = hoedown_buffer_new(size);

    // Clean up by freeing the buffer if it was successfully created
    if (buffer != NULL) {
        hoedown_buffer_free(buffer);
    }

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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
