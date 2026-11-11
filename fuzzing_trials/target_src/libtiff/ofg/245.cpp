#include <cstdint>
#include <cstdlib>
#include <cstring>  // Include this for memcpy

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    TIFF *tiff = TIFFOpen("temp.tiff", "w");
    if (tiff == nullptr) {
        return 0;
    }

    // Allocate a buffer for the TIFFWriteBufferSetup
    tmsize_t bufferSize = static_cast<tmsize_t>(size);
    void *buffer = malloc(bufferSize);
    if (buffer == nullptr) {
        TIFFClose(tiff);
        return 0;
    }

    // Copy data into the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    TIFFWriteBufferSetup(tiff, buffer, bufferSize);

    // Clean up
    free(buffer);
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_245(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
