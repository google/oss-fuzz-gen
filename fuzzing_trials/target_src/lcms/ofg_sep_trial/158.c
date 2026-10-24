#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Initialize the parameters for cmsAppendNamedColor
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Ensure the data size is sufficient for our needs
    if (size < 32 + 3 * sizeof(cmsUInt16Number)) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }

    // Extract a color name from the data
    char colorName[32];
    memcpy(colorName, data, 31);
    colorName[31] = '\0'; // Ensure null-termination

    // Extract PCS and device coordinates from the data
    cmsUInt16Number pcsCoords[3];
    cmsUInt16Number deviceCoords[3];
    memcpy(pcsCoords, data + 32, 3 * sizeof(cmsUInt16Number));
    memcpy(deviceCoords, data + 32 + 3 * sizeof(cmsUInt16Number), 3 * sizeof(cmsUInt16Number));

    // Call the function-under-test
    cmsAppendNamedColor(namedColorList, colorName, pcsCoords, deviceCoords);

    // Clean up
    cmsFreeNamedColorList(namedColorList);

    return 0;
}