#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Initialize a hoedown_buffer
    hoedown_buffer buffer;
    buffer.data = (uint8_t *)malloc(size);
    if (buffer.data == NULL) {
        return 0; // Memory allocation failed, exit gracefully
    }
    buffer.size = size;
    buffer.asize = size;
    buffer.unit = 1;

    // Copy data into the buffer
    memcpy(buffer.data, data, size);

    // Call the function-under-test
    int result = hoedown_buffer_eq(&buffer, data, size);

    // Clean up
    free(buffer.data);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
