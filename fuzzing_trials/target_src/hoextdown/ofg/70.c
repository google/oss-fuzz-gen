#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for creating a meaningful test case
    if (size < 2) {
        return 0;
    }

    // Initialize hoedown_buffer
    hoedown_buffer buffer;
    buffer.data = (uint8_t *)data; // Cast data to uint8_t* for buffer
    buffer.size = size;
    buffer.asize = size;
    buffer.unit = 1;

    // Create a null-terminated string from the input data
    char str[size + 1];
    memcpy(str, data, size);
    str[size] = '\0';

    // Call the function-under-test
    int result = hoedown_buffer_eqs(&buffer, str);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
