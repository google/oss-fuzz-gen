#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *namedColorList;

    // Initialize a named color list with some arbitrary values
    namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Add a named color to the list to ensure it's not empty
    cmsNamedColorInfo(namedColorList, 0, "ColorName", "ColorPrefix", "ColorSuffix", NULL, NULL);

    // Call the function under test
    cmsFreeNamedColorList(namedColorList);

    return 0;
}