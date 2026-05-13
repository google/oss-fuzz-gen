#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_420(const uint8_t *data, size_t size) {
    if (size < 3 * sizeof(cmsUInt16Number)) {
        return 0; // Not enough data to proceed
    }

    cmsCIEXYZ xyz;
    cmsUInt16Number encoded[3];

    // Initialize cmsCIEXYZ structure with some default values
    xyz.X = 0.0;
    xyz.Y = 0.0;
    xyz.Z = 0.0;

    // Copy data into the encoded array
    for (int i = 0; i < 3; i++) {
        encoded[i] = ((cmsUInt16Number)data[i * 2] << 8) | (cmsUInt16Number)data[i * 2 + 1];
    }

    // Call the function-under-test
    cmsXYZEncoded2Float(&xyz, encoded);

    return 0;
}