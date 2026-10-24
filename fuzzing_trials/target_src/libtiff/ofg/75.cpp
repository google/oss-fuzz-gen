#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <tiffio.h>

    int TIFFFieldReadCount(const TIFFField *);
    const TIFFField *TIFFFindField(TIFF *, uint32_t, TIFFDataType);
}

extern "C" int LLVMFuzzerTestOneInput_75(const uint8_t *data, size_t size) {
    // Ensure data size is sufficient for a TIFFField structure
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a dummy TIFF structure for testing
    TIFF *tiff = TIFFOpen("/dev/null", "r");
    if (!tiff) {
        return 0;
    }

    // Extract a field tag from the input data
    uint32_t tag = *reinterpret_cast<const uint32_t *>(data);

    // Find a TIFFField using the tag
    const TIFFField *field = TIFFFindField(tiff, tag, TIFF_NOTYPE);
    if (!field) {
        TIFFClose(tiff);
        return 0;
    }

    // Call the function-under-test
    int readCount = TIFFFieldReadCount(field);

    // Use the result in some way to prevent compiler optimizations from removing the call
    volatile int result = readCount;
    (void)result;

    // Clean up
    TIFFClose(tiff);

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

    LLVMFuzzerTestOneInput_75(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
