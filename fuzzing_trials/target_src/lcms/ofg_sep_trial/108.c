#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read from
    if (size < sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Allocate and initialize variables
    cmsUInt16Number encoded[3]; // Array to hold the encoded XYZ values
    cmsCIEXYZ inputXYZ;

    // Copy data to inputXYZ, ensuring we don't read beyond size
    memcpy(&inputXYZ, data, sizeof(cmsCIEXYZ));

    // Call the function-under-test
    cmsFloat2XYZEncoded(encoded, &inputXYZ);

    return 0;
}