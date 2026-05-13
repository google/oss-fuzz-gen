extern "C" {
    #include <tiffio.h>
    #include <cstdio>
}

extern "C" {
    // Define a custom warning handler outside of the function
    void customWarningHandler(const char* module, const char* fmt, va_list ap) {
        // Custom handler logic (for fuzzing, we can keep it simple)
        if (module != nullptr) {
            // Do something with module, e.g., print it
        }
        if (fmt != nullptr) {
            // Do something with fmt, e.g., print it
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Set the custom warning handler
    TIFFErrorHandler previousHandler = TIFFSetWarningHandler(customWarningHandler);

    // Create a memory-mapped file from the input data
    if (size < 4) {
        // Not enough data to be a valid TIFF file
        return 0;
    }

    // Create a temporary file to simulate a TIFF file
    FILE *tempFile = tmpfile();
    if (!tempFile) {
        TIFFSetWarningHandler(previousHandler);
        return 0;
    }

    // Write the data to the temporary file
    fwrite(data, 1, size, tempFile);
    fseek(tempFile, 0, SEEK_SET);

    // Open the TIFF file from the temporary file
    TIFF *tif = TIFFFdOpen(fileno(tempFile), "memory", "r");
    if (tif) {
        // Perform some operations on the TIFF file
        uint32 width, height;
        uint16 samplesPerPixel;
        if (TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width) &&
            TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height) &&
            TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samplesPerPixel)) {
            // Further processing can be done here
        }
        TIFFClose(tif);
    }

    // Close the temporary file
    fclose(tempFile);

    // Restore the previous warning handler
    TIFFSetWarningHandler(previousHandler);

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

    LLVMFuzzerTestOneInput_179(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
