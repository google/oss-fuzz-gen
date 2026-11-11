#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_303(const uint8_t *data, size_t size) {
    // Ensure there's enough data for three cmsCIEXYZ structures
    if (size < 3 * sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Initialize cmsCIEXYZ structures from the input data
    cmsCIEXYZ input1, input2, input3;
    cmsCIELab output;

    // Copy data into cmsCIEXYZ structures
    memcpy(&input1, data, sizeof(cmsCIEXYZ));
    memcpy(&input2, data + sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));
    memcpy(&input3, data + 2 * sizeof(cmsCIEXYZ), sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsXYZ2Lab(&input1, &output, &input2);

    return 0;
}