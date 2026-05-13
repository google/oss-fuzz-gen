#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libbpf.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure the size is at least enough to extract an integer and a string
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract an integer from the data
    int err_code = *(int *)data;

    // Calculate the remaining size for the buffer
    size_t buffer_size = size - sizeof(int);

    // Allocate memory for the buffer
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        return 0;
    }

    // Copy the remaining data into the buffer
    memcpy(buffer, data + sizeof(int), buffer_size - 1);

    // Null-terminate the buffer
    buffer[buffer_size - 1] = '\0';

    // Call the function-under-test
    libbpf_strerror(err_code, buffer, buffer_size);

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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
