#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_337(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient for cmsUInt16Number array
    if (size < sizeof(cmsUInt16Number) * 3) {
        return 0;
    }

    // Allocate and initialize cmsCIELab structure
    cmsCIELab lab;
    lab.L = 0.0;
    lab.a = 0.0;
    lab.b = 0.0;

    // Cast the input data to cmsUInt16Number array
    const cmsUInt16Number *encodedLab = (const cmsUInt16Number *)data;

    // Call the function-under-test
    cmsLabEncoded2Float(&lab, encodedLab);

    return 0;
}