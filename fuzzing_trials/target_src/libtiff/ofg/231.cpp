#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" {
    // Include necessary headers for the TIFF library
    #include <tiffio.h>
}

// Function-under-test
extern "C" void TIFFOpenOptionsSetMaxSingleMemAlloc(TIFFOpenOptions *, tmsize_t);

extern "C" int LLVMFuzzerTestOneInput_231(const uint8_t *data, size_t size) {
    // Initialize TIFFOpenOptions
    TIFFOpenOptions *options = TIFFOpenOptionsAlloc();
    if (options == NULL) {
        return 0; // Return if allocation fails
    }

    // Ensure that the size is sufficient to extract meaningful data
    if (size < sizeof(tmsize_t)) {
        TIFFOpenOptionsFree(options);
        return 0;
    }

    // Use the first few bytes of data to determine the tmsize_t value
    tmsize_t maxSingleMemAlloc = 0;
    for (size_t i = 0; i < sizeof(tmsize_t) && i < size; ++i) {
        maxSingleMemAlloc = (maxSingleMemAlloc << 8) | data[i];
    }

    // Call the function-under-test
    TIFFOpenOptionsSetMaxSingleMemAlloc(options, maxSingleMemAlloc);

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

    LLVMFuzzerTestOneInput_231(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
