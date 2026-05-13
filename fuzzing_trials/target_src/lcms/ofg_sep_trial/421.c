#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_421(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for cmsUInt16Number array
    if (size < sizeof(cmsUInt16Number) * 3) {
        return 0;
    }

    // Initialize cmsCIEXYZ structure
    cmsCIEXYZ xyz;
    xyz.X = 0.0;
    xyz.Y = 0.0;
    xyz.Z = 0.0;

    // Cast data to cmsUInt16Number pointer
    const cmsUInt16Number* encodedData = (const cmsUInt16Number*)data;

    // Call the function-under-test
    cmsXYZEncoded2Float(&xyz, encodedData);

    return 0;
}