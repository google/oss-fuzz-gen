#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(cmsUInt16Number) * 2 + 1) {
        return 0;
    }

    // Initialize the named color list
    cmsNAMEDCOLORLIST* namedColorList = cmsAllocNamedColorList(NULL, 0, 1, "prefix", "suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Extract the color name from the data
    char colorName[32];
    size_t colorNameLength = size < 31 ? size : 31;
    memcpy(colorName, data, colorNameLength);
    colorName[colorNameLength] = '\0';

    // Extract the PCS and device values from the data
    cmsUInt16Number pcsValues[3];
    cmsUInt16Number deviceValues[3];
    memcpy(pcsValues, data + colorNameLength, sizeof(cmsUInt16Number) * 3);
    memcpy(deviceValues, data + colorNameLength + sizeof(cmsUInt16Number) * 3, sizeof(cmsUInt16Number) * 3);

    // Call the function under test
    cmsBool result = cmsAppendNamedColor(namedColorList, colorName, pcsValues, deviceValues);

    // Clean up
    cmsFreeNamedColorList(namedColorList);

    return 0;
}