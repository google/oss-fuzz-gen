#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_338(const uint8_t *data, size_t size) {
    if (size < sizeof(cmsUInt16Number) * 3) {
        return 0; // Ensure there's enough data for three cmsUInt16Number values
    }

    cmsCIELab lab;
    cmsUInt16Number encoded[3];

    // Initialize encoded values from the input data
    encoded[0] = (cmsUInt16Number)data[0] | ((cmsUInt16Number)data[1] << 8);
    encoded[1] = (cmsUInt16Number)data[2] | ((cmsUInt16Number)data[3] << 8);
    encoded[2] = (cmsUInt16Number)data[4] | ((cmsUInt16Number)data[5] << 8);

    // Call the function under test
    cmsLabEncoded2Float(&lab, encoded);

    return 0;
}