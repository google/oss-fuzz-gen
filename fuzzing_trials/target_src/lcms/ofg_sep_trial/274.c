#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_274(const uint8_t *data, size_t size) {
    if (size < 64) {
        // Ensure there is enough data for the colorant and PCS values
        return 0;
    }

    cmsNAMEDCOLORLIST *namedColorList;
    cmsContext contextID = cmsCreateContext(NULL, NULL);
    
    // Create a named color list with at least one color entry to ensure it's not NULL
    // Fix: Remove the extra NULL argument and provide both Prefix and Suffix
    namedColorList = cmsAllocNamedColorList(contextID, 1, 32, "Prefix", "Suffix");

    if (namedColorList != NULL) {
        // Add a dummy named color to the list
        char name[32] = "ColorName";
        char prefix[32] = "Prefix";
        char suffix[32] = "Suffix";
        cmsNamedColorInfo(namedColorList, 0, name, prefix, suffix, (cmsUInt16Number *)data, (cmsUInt16Number *)(data + 32));

        // Call the function-under-test
        cmsUInt32Number colorCount = cmsNamedColorCount(namedColorList);

        // Clean up
        cmsFreeNamedColorList(namedColorList);
    }

    cmsDeleteContext(contextID);

    return 0;
}