#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Declare and initialize the variables
    cmsCIELab lab;
    cmsUInt16Number encoded[3];

    // Ensure size is sufficient for cmsUInt16Number array
    if (size < sizeof(encoded)) {
        return 0;
    }

    // Copy data into encoded array, ensuring no overflow
    for (size_t i = 0; i < 3; i++) {
        encoded[i] = (cmsUInt16Number)((data[i * 2] << 8) | data[i * 2 + 1]);
    }

    // Call the function under test
    cmsLabEncoded2FloatV2(&lab, encoded);

    return 0;
}