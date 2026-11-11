#include <stdint.h>
#include <tiffio.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    TIFF *tiff;
    uint32_t strip = 0;
    tmsize_t result;

    // Create a temporary TIFF file in memory
    tiff = TIFFOpen("temp.tiff", "w");
    if (tiff == NULL) {
        return 0;
    }

    // Ensure the data size is non-zero for writing
    if (size == 0) {
        size = 1;
    }

    // Allocate memory for the buffer
    void *buffer = malloc(size);
    if (buffer == NULL) {
        TIFFClose(tiff);
        return 0;
    }

    // Copy the input data to the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    result = TIFFWriteRawStrip(tiff, strip, buffer, (tmsize_t)size);

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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
