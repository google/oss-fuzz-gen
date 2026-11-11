#include <cstdint>
#include <tiffio.h>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Create a temporary file to hold the TIFF data
    FILE *tempFile = tmpfile();
    if (tempFile == nullptr) {
        return 0; // Return if temp file creation failed
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, tempFile) != size) {
        fclose(tempFile);
        return 0; // Return if writing to the file failed
    }

    // Rewind the file to the beginning
    rewind(tempFile);

    // Open the temporary file as a TIFF image
    TIFF *tiff = TIFFFdOpen(fileno(tempFile), "dummy.tiff", "r");
    if (tiff == nullptr) {
        fclose(tempFile);
        return 0; // Return if TIFF object creation failed
    }

    uint32_t tileWidth = 0;
    uint32_t tileLength = 0;

    // Call the function-under-test
    TIFFDefaultTileSize(tiff, &tileWidth, &tileLength);

    // Close the TIFF object
    TIFFClose(tiff);

    // Close the temporary file
    fclose(tempFile);

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

    LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
