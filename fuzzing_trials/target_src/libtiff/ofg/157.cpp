#include <cstdint>
#include <cstdlib>

extern "C" {
    #include <tiffio.h>
}

// Function-under-test declaration
extern "C" void TIFFCIELabToXYZ(TIFFCIELabToRGB *, uint32_t, int32_t, int32_t, float *, float *, float *);

extern "C" int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Define and initialize variables
    TIFFCIELabToRGB cielabToRGB;
    uint32_t sample = 0;
    int32_t a = 0;
    int32_t b = 0;
    float X = 0.0f;
    float Y = 0.0f;
    float Z = 0.0f;

    // Ensure that size is sufficient to extract meaningful data
    if (size < sizeof(uint32_t) + 2 * sizeof(int32_t)) {
        return 0;
    }

    // Use input data to initialize variables
    sample = *reinterpret_cast<const uint32_t*>(data);
    a = *reinterpret_cast<const int32_t*>(data + sizeof(uint32_t));
    b = *reinterpret_cast<const int32_t*>(data + sizeof(uint32_t) + sizeof(int32_t));

    // Call the function-under-test
    TIFFCIELabToXYZ(&cielabToRGB, sample, a, b, &X, &Y, &Z);

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

    LLVMFuzzerTestOneInput_157(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
