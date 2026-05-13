#include <stdint.h>
#include <stddef.h>
#include <tiffio.h>

extern "C" {
    #include <tiffio.h>
}

// Define a constant for the maximum TIFFDataType value
#define TIFF_MAXDATATYPE 13

extern "C" int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < sizeof(TIFFDataType)) {
        return 0;
    }

    // Interpret the input data as a TIFFDataType
    TIFFDataType dataType = static_cast<TIFFDataType>(data[0] % TIFF_MAXDATATYPE);

    // Call the function-under-test
    int width = TIFFDataWidth(dataType);

    // Use the result in some way to prevent the compiler from optimizing it out
    (void)width;

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
