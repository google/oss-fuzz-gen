#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for the function-under-test
    cmsCIELab lab;
    cmsUInt16Number encoded[3];

    // Ensure the size is sufficient to fill the encoded array
    if (size < sizeof(encoded)) {
        return 0;
    }

    // Copy data into the encoded array
    for (size_t i = 0; i < 3; i++) {
        encoded[i] = (cmsUInt16Number)((data[i * 2] << 8) | data[i * 2 + 1]);
    }

    // Call the function-under-test
    cmsLabEncoded2FloatV2(&lab, encoded);

    return 0;
}