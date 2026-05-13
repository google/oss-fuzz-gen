#include <cstdint>
#include <cstdlib>
#include <cstdarg>

extern "C" {
#include <tiffio.h>

// Define a custom warning handler that matches the TIFFErrorHandlerExtR signature
int CustomWarningHandler_30(struct tiff* tif, void* clientData, const char* module, const char* fmt, va_list ap) {
    // Custom handling of warnings
    return 0; // Return 0 to indicate success
}

// Fuzzing harness for TIFFOpenOptionsSetWarningHandlerExtR
int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize TIFFOpenOptions
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        return 0; // Allocation failed, exit early
    }

    // Use the data as a pointer for the client data (void* parameter)
    void *clientData = (void*)data;

    // Call the function under test
    TIFFOpenOptionsSetWarningHandlerExtR(options, CustomWarningHandler_30, clientData);

    // Attempt to open a TIFF file with the options to ensure the function is utilized
    TIFF *tif = TIFFOpen("dummy.tiff", "r");
    if (tif != nullptr) {
        TIFFClose(tif);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
