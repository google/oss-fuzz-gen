#include <sys/stat.h>
#include <string.h>
#include "tiffio.h"
#include "cstdint"
#include <cstddef>
#include <cstdio> // For std::tmpfile

extern "C" {
    // Define a custom error handler function
    void customErrorHandler_61(const char* module, const char* fmt, va_list ap) {
        // Custom handling of the error messages can be implemented here
        // For this example, we'll just ignore the error messages
    }
}

extern "C" int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Ensure that the custom error handler is set
    TIFFErrorHandler previousHandler = TIFFSetErrorHandler(customErrorHandler_61);

    // Create a temporary file to write the input data
    FILE* tempFile = std::tmpfile();
    if (!tempFile) {
        return 0; // Failed to create a temporary file
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, tempFile) != size) {
        fclose(tempFile);
        return 0; // Failed to write data to the temporary file
    }

    // Rewind the file to the beginning
    rewind(tempFile);

    // Open the temporary file as a TIFF image
    TIFF* tif = TIFFFdOpen(fileno(tempFile), "tempfile", "r");
    if (tif) {
        // Perform operations on the TIFF image
        // For example, read the number of directories
        uint16_t dirCount = 0;
        do {
            dirCount++;
        } while (TIFFReadDirectory(tif));

        // Close the TIFF image
        TIFFClose(tif);
    }

    // Close the temporary file
    fclose(tempFile);

    // Reset the error handler to the previous one after the test
    TIFFSetErrorHandler(previousHandler);

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

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
