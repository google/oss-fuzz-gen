#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Ensure that the size is greater than 0 to have at least one character for the string
    if (size == 0) {
        return 0;
    }

    // Allocate and initialize a hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(size);
    if (buffer == NULL) {
        return 0;
    }

    // Copy data into the hoedown_buffer
    hoedown_buffer_put(buffer, data, size);

    // Create a null-terminated string from the data
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        hoedown_buffer_free(buffer);
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Call the function-under-test
    int result = hoedown_buffer_eqs(buffer, str);

    // Clean up
    free(str);
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
