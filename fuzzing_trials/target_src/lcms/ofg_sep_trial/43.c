#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Initialize a cmsNAMEDCOLORLIST object
    cmsNAMEDCOLORLIST *originalList = cmsAllocNamedColorList(NULL, 1, 0, "Prefix", "Suffix");
    if (originalList == NULL) {
        return 0;
    }

    // Add a named color to the list
    const char *colorName = "TestColor";
    cmsCIEXYZ pcs = {0.5, 0.5, 0.5};
    cmsUInt16Number deviceColorant[4] = {32768, 32768, 32768, 32768}; // 0.5 in 16-bit

    if (!cmsAppendNamedColor(originalList, colorName, &pcs, deviceColorant)) {
        cmsFreeNamedColorList(originalList);
        return 0;
    }

    // Call the function-under-test
    cmsNAMEDCOLORLIST *duplicatedList = cmsDupNamedColorList(originalList);

    // Clean up
    if (duplicatedList != NULL) {
        cmsFreeNamedColorList(duplicatedList);
    }
    cmsFreeNamedColorList(originalList);

    return 0;
}