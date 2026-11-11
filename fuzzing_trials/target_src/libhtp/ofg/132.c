#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Include the correct header file for the function bstr_util_mem_trim
#include "/src/libhtp/htp/bstr.h"

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    // Allocate memory for the buffer and ensure it is not NULL
    unsigned char *buffer = (unsigned char *)malloc(size + 1);
    if (buffer == NULL) {
        return 0;
    }

    // Copy the input data to the buffer and null-terminate it
    memcpy(buffer, data, size);
    buffer[size] = '\0';

    // Initialize a size_t variable
    size_t buffer_size = size;

    // Call the function-under-test
    bstr_util_mem_trim(&buffer, &buffer_size);

    // Free the allocated memory
    free(buffer);

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

    LLVMFuzzerTestOneInput_132(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
