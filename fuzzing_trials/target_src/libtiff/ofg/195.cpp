#include <cstdint>
#include <cstdlib>

extern "C" {
    #include <tiffio.h>

    // Function signature for the function-under-test
    void TIFFXYZToRGB(TIFFCIELabToRGB *, float, float, float, uint32_t *, uint32_t *, uint32_t *);
}

extern "C" int LLVMFuzzerTestOneInput_195(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for extracting float values and pointers
    if (size < sizeof(float) * 3 + sizeof(uint32_t) * 3) {
        return 0;
    }

    // Initialize the TIFFCIELabToRGB structure
    TIFFCIELabToRGB cielab;
    TIFFDisplay display = {
        { 3.240479f, -1.537150f, -0.498535f, -0.969256f, 1.875992f, 0.041556f, 0.055648f, -0.204043f, 1.057311f }
    }; // Corrected to match the expected initializer
    float refWhite[3] = { 0.964202f, 1.000000f, 0.824905f }; // D65 reference white point

    // Correct the function call to provide the required arguments
    TIFFCIELabToRGBInit(&cielab, &display, refWhite);

    // Extract float values from input data
    float X = *reinterpret_cast<const float*>(data);
    float Y = *reinterpret_cast<const float*>(data + sizeof(float));
    float Z = *reinterpret_cast<const float*>(data + 2 * sizeof(float));

    // Extract pointers to uint32_t from input data
    uint32_t R, G, B;
    uint32_t *pR = &R;
    uint32_t *pG = &G;
    uint32_t *pB = &B;

    // Call the function-under-test
    TIFFXYZToRGB(&cielab, X, Y, Z, pR, pG, pB);

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

    LLVMFuzzerTestOneInput_195(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
