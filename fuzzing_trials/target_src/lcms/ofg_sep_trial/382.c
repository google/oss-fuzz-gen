#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_382(const uint8_t *data, size_t size) {
    // Ensure there is enough data for a non-empty string
    if (size < 1) return 0;

    // Create a dummy named color list
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) return 0;

    // Add a dummy color to the list
    cmsUInt16Number pcs[3] = {0, 0, 0}; // Dummy PCS values
    cmsUInt16Number colorant[3] = {0, 0, 0}; // Dummy colorant values
    cmsNamedColorInfo(namedColorList, 0, "DummyColorName", "Prefix", "Suffix", pcs, colorant);

    // Allocate memory for the color name string
    char *colorName = (char *)malloc(size + 1);
    if (colorName == NULL) {
        cmsFreeNamedColorList(namedColorList);
        return 0;
    }

    // Copy data to color name and null-terminate
    memcpy(colorName, data, size);
    colorName[size] = '\0';

    // Call the function under test
    cmsInt32Number index = cmsNamedColorIndex(namedColorList, colorName);

    // Clean up
    free(colorName);
    cmsFreeNamedColorList(namedColorList);

    return 0;
}