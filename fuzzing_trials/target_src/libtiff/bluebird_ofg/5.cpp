#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include <cstddef>
#include "cstring"  // Include this for memcpy
#include <cstdio>   // Include this for remove()

extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to represent a double
    if (size < sizeof(double)) {
        return 0; // Not enough data to form a double, exit early
    }

    // Initialize a double variable from the input data
    double value;
    // Copy bytes from data to the double variable
    memcpy(&value, data, sizeof(double));

    // Call the function-under-test
    TIFFSwabDouble(&value);

    // Attempt to use the value after swabbing to ensure coverage
    // For demonstration, we'll just print it to a dummy variable
    volatile double dummy = value; // Use volatile to prevent optimization

    // Additional code to increase coverage
    // Create a TIFF file in memory and perform operations on it
    const char* filename = "temp.tiff";
    TIFF* tiff = TIFFOpen(filename, "w");
    if (tiff) {
        // Set a field to use the swabbed double value
        TIFFSetField(tiff, TIFFTAG_XRESOLUTION, dummy);
        TIFFSetField(tiff, TIFFTAG_YRESOLUTION, dummy);
        TIFFSetField(tiff, TIFFTAG_RESOLUTIONUNIT, RESUNIT_INCH);

        // Perform additional operations to increase code coverage
        TIFFWriteDirectory(tiff);
        TIFFClose(tiff);

        // Attempt to reopen the TIFF file to further increase coverage
        tiff = TIFFOpen(filename, "r");
        if (tiff) {
            double xres, yres;
            uint16_t resunit;
            TIFFGetField(tiff, TIFFTAG_XRESOLUTION, &xres);
            TIFFGetField(tiff, TIFFTAG_YRESOLUTION, &yres);
            TIFFGetField(tiff, TIFFTAG_RESOLUTIONUNIT, &resunit);
            TIFFClose(tiff);
        }

        // Clean up by removing the temporary TIFF file
        remove(filename);
    }

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
