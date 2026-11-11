#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" {
    // Function signature from the provided task
    void TIFFReverseBits(uint8_t *, tmsize_t);
}

extern "C" int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Allocate memory for the buffer to be reversed
    uint8_t *buffer = (uint8_t *)malloc(size);
    if (buffer == nullptr) {
        return 0; // Exit if memory allocation fails
    }

    // Copy input data to the buffer
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = data[i];
    }

    // Call the function-under-test
    TIFFReverseBits(buffer, (tmsize_t)size);

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

    LLVMFuzzerTestOneInput_147(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
