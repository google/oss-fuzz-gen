#include <cstdint>
#include <cstdarg>
#include <tiffio.h>

extern "C" {

// Corrected function signature to match TIFFErrorHandlerExt
void customErrorHandler_10(void* module, const char* fmt, const char* format, va_list ap) {
    // Custom error handling logic, for now just do nothing
}

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Set the custom error handler using the function-under-test
    TIFFErrorHandlerExt prevHandler = TIFFSetErrorHandlerExt(customErrorHandler_10);

    // Restore the previous error handler
    TIFFSetErrorHandlerExt(prevHandler);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
