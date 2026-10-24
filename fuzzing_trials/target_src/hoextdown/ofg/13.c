#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure that the size is at least 2 to have a non-empty format string and a valid argument
    if (size < 2) {
        return 0;
    }

    // Initialize hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(64);
    if (buffer == NULL) {
        return 0;
    }

    // Use the first byte of data as the format string
    char format[2];
    format[0] = (char)data[0];
    format[1] = '\0';

    // Use the second byte of data as an argument for the format string
    int arg = (int)data[1];

    // Call the function-under-test
    hoedown_buffer_printf(buffer, format, arg);

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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
