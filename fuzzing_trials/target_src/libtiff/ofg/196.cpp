#include <cstdint>
#include <cstdlib>
#include <cstring>

// Assuming the necessary TIFF headers are available and included here
extern "C" {
    #include "tiffio.h"
}

extern "C" int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    // Initialize the variables needed for the function call
    TIFFCIELabToRGB cielabToRGB;
    float X = 0.0f;
    float Y = 0.0f;
    float Z = 0.0f;
    uint32_t R = 0;
    uint32_t G = 0;
    uint32_t B = 0;

    // Check if we have enough data to extract three floats
    if (size >= sizeof(float) * 3) {
        // Extract floats from the data
        std::memcpy(&X, data, sizeof(float));
        std::memcpy(&Y, data + sizeof(float), sizeof(float));
        std::memcpy(&Z, data + 2 * sizeof(float), sizeof(float));
    } else {
        // If not enough data, return early
        return 0;
    }

    // Initialize the cielabToRGB structure with some default values
    cielabToRGB.range = 255; // Assuming 8-bit color depth
    cielabToRGB.X0 = 0.95047f; // D65 standard illuminant
    cielabToRGB.Y0 = 1.00000f;
    cielabToRGB.Z0 = 1.08883f;

    // Validate and adjust the input values to ensure they are within a reasonable range
    // This helps in exploring valid code paths
    if (X < 0.0f) X = 0.0f;
    if (Y < 0.0f) Y = 0.0f;
    if (Z < 0.0f) Z = 0.0f;

    // Call the function-under-test
    TIFFXYZToRGB(&cielabToRGB, X, Y, Z, &R, &G, &B);

    // Utilize the output in some way to ensure coverage
    volatile uint32_t outputR = R;
    volatile uint32_t outputG = G;
    volatile uint32_t outputB = B;

    // Prevent the compiler from optimizing away the usage
    (void)outputR;
    (void)outputG;
    (void)outputB;

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

    LLVMFuzzerTestOneInput_196(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
