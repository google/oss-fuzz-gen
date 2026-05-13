#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    // Ensure size is large enough to extract parameters
    if (size < sizeof(int) + sizeof(tmsize_t)) {
        return 0;
    }

    // Extract the int value from the data
    int int_value = static_cast<int>(data[0]);

    // Extract the tmsize_t value from the data
    tmsize_t tmsize_value = static_cast<tmsize_t>(size - sizeof(int));

    // Ensure tmsize_value is positive and within reasonable limits
    if (tmsize_value <= 0 || tmsize_value > size - sizeof(int)) {
        return 0;
    }

    // Allocate memory for the void pointer
    void *buffer = malloc(tmsize_value);
    if (buffer == NULL) {
        return 0;
    }

    // Fill the buffer with the remaining data
    memcpy(buffer, data + sizeof(int), tmsize_value);

    // Call the function-under-test with valid parameters
    // Ensure that int_value is a valid value for memset operation
    int_value = int_value % 256; // Ensure int_value is within 0-255

    _TIFFmemset(buffer, int_value, tmsize_value);

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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
