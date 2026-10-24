#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <string.h> // Include for memcpy

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize input and output structures
    cmsCIEXYZ inputXYZ;
    cmsCIEXYZ outputXYZ;
    cmsCIELab inputLab;

    // Copy data into the inputLab structure
    // Ensure the data is interpreted correctly as cmsCIELab
    memcpy(&inputLab, data, sizeof(cmsCIELab));

    // Initialize inputXYZ with some non-null values
    inputXYZ.X = 0.5;
    inputXYZ.Y = 0.5;
    inputXYZ.Z = 0.5;

    // Call the function under test
    cmsLab2XYZ(&inputXYZ, &outputXYZ, &inputLab);

    return 0;
}