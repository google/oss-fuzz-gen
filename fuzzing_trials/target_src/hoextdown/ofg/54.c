#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h" // Correct path for hoedown_buffer

int LLVMFuzzerTestOneInput_54(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to avoid empty data
    if (size == 0) return 0;

    // Allocate and initialize hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(size);
    if (buffer == NULL) return 0;

    // Create a null-terminated string from the input data
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        hoedown_buffer_free(buffer);
        return 0;
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    hoedown_buffer_sets(buffer, input_str);

    // Clean up
    free(input_str);
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

    LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
