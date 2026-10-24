#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    cmsNAMEDCOLORLIST *namedColorList = NULL;
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Create a named color list with at least one color to avoid NULL
    namedColorList = cmsAllocNamedColorList(context, 1, 0, "Prefix", "Suffix");
    if (namedColorList != NULL) {
        // Use the input data to create a color name
        char colorName[256];
        size_t colorNameLength = size < 255 ? size : 255;
        memcpy(colorName, data, colorNameLength);
        colorName[colorNameLength] = '\0'; // Ensure null termination

        // Append a named color using the input data
        cmsUInt16Number ColorXYZ[3] = {32768, 32768, 32768}; // Example color value in 16-bit
        cmsUInt16Number PCSXYZ[3] = {19660, 19660, 19660};   // Example PCS value in 16-bit

        // Attempt to append the named color
        if (cmsAppendNamedColor(namedColorList, colorName, PCSXYZ, ColorXYZ)) {
            // Additional operations to increase code coverage
            // Retrieve the color index
            int colorIndex = cmsNamedColorIndex(namedColorList, colorName);
            if (colorIndex != -1) {
                // Retrieve the color value
                cmsUInt16Number retrievedPCSXYZ[3];
                cmsUInt16Number retrievedColorant[3];
                if (cmsNamedColorInfo(namedColorList, colorIndex, colorName, NULL, NULL, retrievedPCSXYZ, retrievedColorant)) {
                    // Further operations can be performed if needed
                }
            }
        }
    }

    // Call the function under test
    cmsFreeNamedColorList(namedColorList);

    // Clean up the context
    cmsDeleteContext(context);

    return 0;
}