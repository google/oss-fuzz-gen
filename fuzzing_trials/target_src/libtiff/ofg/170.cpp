#include <tiffio.h>
#include <cstdint>
#include <cstdlib>
#include <cstdarg>

extern "C" {

void CustomErrorHandler(const char* module, const char* fmt, va_list ap) {
    // Custom error handling logic can be implemented here
}

int CustomErrorHandlerExtR(TIFF* tiff, void* userData, const char* module, const char* fmt, va_list ap) {
    CustomErrorHandler(module, fmt, ap);
    return 0; // Return 0 to indicate no error
}

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    TIFFOpenOptions *options;
    TIFFErrorHandlerExtR errorHandler = CustomErrorHandlerExtR;
    void *userData = reinterpret_cast<void*>(0xDEADBEEF); // Arbitrary non-null pointer

    // Initialize TIFFOpenOptions
    options = TIFFOpenOptionsAlloc();
    if (options == NULL) {
        return 0;
    }

    // Call the function-under-test
    TIFFOpenOptionsSetErrorHandlerExtR(options, errorHandler, userData);

    // Cleanup
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

    LLVMFuzzerTestOneInput_170(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
