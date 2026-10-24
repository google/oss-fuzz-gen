#include <cstdint>
#include <cstdlib>
#include <cstdarg>

// Include necessary TIFF headers and wrap them in extern "C"
extern "C" {
    #include <tiffio.h>

    // Define a sample error handler function that matches the TIFFErrorHandlerExtR signature
    int sampleErrorHandler(struct tiff *tif, void *clientData, const char* module, const char* fmt, va_list ap) {
        // Simple error handler that does nothing
        return 0;
    }
}

extern "C" int LLVMFuzzerTestOneInput_171(const uint8_t *data, size_t size) {
    // Initialize the TIFFOpenOptions structure
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        return 0; // Exit if allocation fails
    }

    // Use the first byte of data as a pointer to pass to the error handler
    void *clientData = (void *)(uintptr_t)(data[0]);

    // Call the function-under-test
    TIFFOpenOptionsSetErrorHandlerExtR(options, sampleErrorHandler, clientData);

    // Clean up
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

    LLVMFuzzerTestOneInput_171(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
