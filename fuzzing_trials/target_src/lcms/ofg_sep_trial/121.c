#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    // Declare and initialize input and output structures
    cmsCIEXYZ inputXYZ = {0.0, 0.0, 0.0};
    cmsCIEXYZ outputXYZ = {0.0, 0.0, 0.0};
    cmsCIELab inputLab = {0.0, 0.0, 0.0};

    // Ensure there is enough data to populate the structures
    if (size < sizeof(cmsCIEXYZ) + sizeof(cmsCIELab)) {
        return 0;
    }

    // Populate the input structures with data
    // Use memcpy to safely copy data into the structures
    memcpy(&inputXYZ, data, sizeof(cmsCIEXYZ));
    memcpy(&inputLab, data + sizeof(cmsCIEXYZ), sizeof(cmsCIELab));

    // Call the function-under-test
    cmsLab2XYZ(&inputXYZ, &outputXYZ, &inputLab);

    return 0;
}