#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    cmsUInt16Number labEncoded[3];
    cmsCIELab lab;

    // Ensure there is enough data to fill the cmsCIELab structure
    if (size < sizeof(cmsCIELab)) {
        return 0;
    }

    // Initialize the cmsCIELab structure with data from the input
    lab.L = ((const float *)data)[0];
    lab.a = ((const float *)data)[1];
    lab.b = ((const float *)data)[2];

    // Call the function-under-test
    cmsFloat2LabEncodedV2(labEncoded, &lab);

    return 0;
}