#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>
#include <iostream>

extern "C" {
    int TIFFCIELabToRGBInit(TIFFCIELabToRGB *, const TIFFDisplay *, float *);
}

extern "C" int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the parameters
    if (size < sizeof(TIFFCIELabToRGB) + sizeof(TIFFDisplay) + 3 * sizeof(float)) {
        return 0;
    }

    // Initialize TIFFCIELabToRGB structure from data
    TIFFCIELabToRGB cielab;
    std::memcpy(&cielab, data, sizeof(TIFFCIELabToRGB));
    TIFFCIELabToRGB *cielabPtr = &cielab;

    // Move the data pointer forward
    data += sizeof(TIFFCIELabToRGB);
    size -= sizeof(TIFFCIELabToRGB);

    // Initialize TIFFDisplay structure from data
    TIFFDisplay display;
    std::memcpy(&display, data, sizeof(TIFFDisplay));
    const TIFFDisplay *displayPtr = &display;

    // Move the data pointer forward
    data += sizeof(TIFFDisplay);
    size -= sizeof(TIFFDisplay);

    // Initialize float array from data
    float range[3];
    std::memcpy(range, data, 3 * sizeof(float));

    // Ensure that the range values are within a reasonable range
    for (int i = 0; i < 3; ++i) {
        if (range[i] < 0.0f || range[i] > 1.0f) {
            range[i] = 0.5f; // Set a default value within expected range
        }
    }

    // Print debug information for better understanding of the input
    std::cout << "TIFFCIELabToRGB: " << std::hex << cielabPtr << std::endl;
    std::cout << "TIFFDisplay: " << std::hex << displayPtr << std::endl;
    std::cout << "Range: [" << range[0] << ", " << range[1] << ", " << range[2] << "]" << std::endl;

    // Call the function-under-test
    int result = TIFFCIELabToRGBInit(cielabPtr, displayPtr, range);

    // Check the result for debugging purposes
    std::cout << "TIFFCIELabToRGBInit result: " << result << std::endl;

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

    LLVMFuzzerTestOneInput_226(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
