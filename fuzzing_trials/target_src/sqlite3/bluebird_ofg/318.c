#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "sqlite3.h"
#include <string.h>

int LLVMFuzzerTestOneInput_318(const uint8_t *data, size_t size) {
    // Ensure that the size is a multiple of 2 to simulate UTF-16 encoding
    if (size < 2 || size % 2 != 0) {
        return 0;
    }

    // Allocate a new buffer with an additional null terminator
    uint8_t *null_terminated_data = (uint8_t *)malloc(size + 2);
    if (!null_terminated_data) {
        return 0; // If allocation fails, exit early
    }

    // Copy the input data to the new buffer
    memcpy(null_terminated_data, data, size);

    // Add a null terminator for UTF-16 (two null bytes)
    null_terminated_data[size] = 0;
    null_terminated_data[size + 1] = 0;

    // Call the function-under-test with the provided data
    int result = sqlite3_complete16((const void *)null_terminated_data);

    // Free the allocated buffer
    free(null_terminated_data);

    // Return 0 to indicate the fuzzer should continue
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_318(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
