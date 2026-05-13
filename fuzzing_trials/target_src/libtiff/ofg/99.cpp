#include <cstddef>
#include <cstdint>
#include <tiffio.h>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Create a memory stream from the input data
    if (size == 0) {
        return 0;
    }

    // Open a TIFF image from the memory buffer
    TIFF* tiff = TIFFOpen("memory", "rm");
    if (tiff == nullptr) {
        return 0;
    }

    // Set the memory buffer as the input for the TIFF object
    if (!TIFFClientOpen("memory", "rm", (thandle_t)data, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
        TIFFClose(tiff);
        return 0;
    }

    // Read the directory of the TIFF image
    do {
        // Perform operations on the TIFF image to increase coverage
        uint32_t width, height;
        TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
        TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);

        // Allocate buffer for reading the image
        tmsize_t npixels = width * height;
        uint32_t* raster = (uint32_t*)_TIFFmalloc(npixels * sizeof(uint32_t));
        if (raster != nullptr) {
            // Read the image into the buffer
            if (TIFFReadRGBAImage(tiff, width, height, raster, 0)) {
                // Successfully read the image, do something with the data
            }
            _TIFFfree(raster);
        }
    } while (TIFFReadDirectory(tiff)); // Move to the next image directory

    // Close the TIFF image
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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
