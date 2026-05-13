#include <sys/stat.h>
#include <string.h>
#include "cstdint"
#include "cstdlib"
#include <cstdarg>
#include "cstring" // Include for memcpy
#include "tiffio.h"

extern "C" {
    // Corrected error handler function signature
    int MyErrorHandler(struct tiff* tif, void* user_data, const char* module, const char* fmt, va_list ap) {
        // Custom error handling logic can be implemented here
        return 0; // Return an integer as expected by TIFFErrorHandlerExtR
    }

    int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
        // Ensure data size is sufficient for testing
        if (size < sizeof(void*)) {
            return 0;
        }

        // Initialize TIFFOpenOptions
        TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
        if (options == NULL) {
            return 0;
        }

        // Cast data to a void pointer for the third parameter
        void *user_data = (void*)(data);

        // Call the function under test with the corrected error handler
        TIFFOpenOptionsSetErrorHandlerExtR(options, MyErrorHandler, user_data);

        // Attempt to open a TIFF from the data
        // Create a memory stream from the input data
        TIFF* tiff = TIFFClientOpen("MemTIFF", "r", (thandle_t)data,
                                    [](thandle_t fd, void* buf, tmsize_t size) -> tmsize_t {
                                        memcpy(buf, (void*)fd, size);
                                        return size;
                                    },
                                    nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        if (tiff) {
            // Perform operations on the TIFF to increase coverage
            uint32_t width, height;
            TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
            TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);

            // Close the TIFF
            TIFFClose(tiff);
        }

        // Clean up
        TIFFOpenOptionsFree(options);

        return 0;
    }
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
