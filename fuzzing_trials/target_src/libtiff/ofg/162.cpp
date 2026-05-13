#include <stdint.h>
#include <stddef.h>

// Include standard libraries first
#include <iostream>
#include <fstream>
#include <string>
#include <memory>

// Wrap project-specific headers in extern "C"
extern "C" {
    #include <tiffio.h>
    // Remove the C++ TIFF interface include as it is not needed and causes issues
    // #include <tiffio.hxx>
}

extern "C" int LLVMFuzzerTestOneInput_162(const uint8_t *data, size_t size) {
    // Declare a TIFFOpenOptions pointer
    TIFFOpenOptions *options = nullptr;

    // Initialize the TIFFOpenOptions
    options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        // If allocation fails, return early
        return 0;
    }

    // Create a memory buffer with the input data
    TIFF *tif = TIFFClientOpen("MemTIFF", "rm", (thandle_t)data,
                               [](thandle_t fd, void *buf, tmsize_t size) -> tmsize_t { return size; },
                               [](thandle_t fd, void *buf, tmsize_t size) -> tmsize_t { return 0; },
                               [](thandle_t fd, toff_t off, int whence) -> toff_t { return 0; },
                               [](thandle_t fd) -> int { return 0; },
                               [](thandle_t fd) -> toff_t { return 0; },
                               nullptr,
                               nullptr); // Add the missing argument for TIFFUnmapFileProc

    if (tif != nullptr) {
        // Perform some operations on the TIFF file to ensure code coverage
        uint32_t width, height;
        TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);

        // Close the TIFF file
        TIFFClose(tif);
    }

    // Free the TIFFOpenOptions
    TIFFOpenOptionsFree(options);

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

    LLVMFuzzerTestOneInput_162(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
