#include <cstdint>
#include <cstddef>
#include <tiffio.h> // Ensure the TIFF library is properly included

extern "C" {
    // Declare the function-under-test
    void TIFFReverseBits(uint8_t *data, tmsize_t size);
}

extern "C" int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to avoid passing a NULL pointer
    if (size == 0) {
        return 0;
    }

    // Allocate memory for the input buffer and copy the data
    uint8_t *buffer = new uint8_t[size];
    for (size_t i = 0; i < size; ++i) {
        buffer[i] = data[i];
    }

    // Call the function-under-test
    TIFFReverseBits(buffer, static_cast<tmsize_t>(size));

    // Clean up the allocated memory
    delete[] buffer;

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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
