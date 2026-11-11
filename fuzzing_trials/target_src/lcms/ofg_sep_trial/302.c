#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_302(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to populate the structures
    if (size < sizeof(cmsCIEXYZ) * 2 + sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the input and output structures
    cmsCIEXYZ input1, whitePoint;
    cmsCIELab output;

    // Copy data into the structures, ensuring no NULL values
    memcpy(&input1, data, sizeof(cmsCIEXYZ));
    memcpy(&whitePoint, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsXYZ2Lab(&input1, &output, &whitePoint);

    return 0;
}