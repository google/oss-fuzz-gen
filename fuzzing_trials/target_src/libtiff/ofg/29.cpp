#include <cstdint>
#include <cstdlib>
#include <cstdarg>
#include <tiffio.h>

extern "C" {

// Correct the function signature to match TIFFErrorHandlerExtR
int CustomWarningHandler_29(struct tiff *tif, void *user_data, const char* module, const char* fmt, va_list ap) {
    // Custom warning handler implementation
    return 0; // Return an int as expected by TIFFErrorHandlerExtR
}

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == nullptr) {
        return 0;
    }

    // Ensure the data is non-NULL and has a valid size
    if (size == 0) {
        size = 1;
    }

    // Use a non-NULL pointer as the third argument
    void *user_data = reinterpret_cast<void*>(const_cast<uint8_t*>(data));

    // Call the function-under-test
    TIFFOpenOptionsSetWarningHandlerExtR(options, CustomWarningHandler_29, user_data);

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
