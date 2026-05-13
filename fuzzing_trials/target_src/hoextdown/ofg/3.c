#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h" // Correct header file for hoedown_buffer

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure that the input size is at least 1 to create a valid null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(size);
    if (buffer == NULL) {
        return 0;
    }

    // Allocate memory for the string and ensure it's null-terminated
    char *input_string = (char *)malloc(size + 1);
    if (input_string == NULL) {
        hoedown_buffer_free(buffer);
        return 0;
    }
    memcpy(input_string, data, size);
    input_string[size] = '\0';

    // Call the function-under-test
    hoedown_buffer_puts(buffer, input_string);

    // Clean up
    free(input_string);
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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
