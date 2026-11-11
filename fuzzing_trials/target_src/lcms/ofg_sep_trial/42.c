#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *originalList = NULL;
    cmsNAMEDCOLORLIST *duplicatedList = NULL;

    // Create a named color list with some dummy values
    originalList = cmsAllocNamedColorList(NULL, 1, 1, "Prefix", "Suffix");
    if (originalList == NULL) {
        return 0;
    }

    // Add a named color to the list
    cmsCIEXYZ PCS = {0.5, 0.5, 0.5};
    cmsUInt16Number DeviceColorant[4] = {0x8000, 0x8000, 0x8000, 0x8000};

    cmsAppendNamedColor(originalList, "TestColor", &PCS, DeviceColorant);

    // Call the function under test
    duplicatedList = cmsDupNamedColorList(originalList);

    // Clean up
    if (duplicatedList != NULL) {
        cmsFreeNamedColorList(duplicatedList);
    }
    if (originalList != NULL) {
        cmsFreeNamedColorList(originalList);
    }

    return 0;
}