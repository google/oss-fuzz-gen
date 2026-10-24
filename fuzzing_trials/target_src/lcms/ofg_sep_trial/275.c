#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_275(const uint8_t *data, size_t size) {
    cmsNAMEDCOLORLIST *namedColorList;
    cmsContext contextID = cmsCreateContext(NULL, NULL);
    cmsUInt32Number result;

    // Create a named color list with a fixed number of colors for testing
    namedColorList = cmsAllocNamedColorList(contextID, 10, 32, "prefix", "suffix");

    // Ensure the namedColorList is not NULL
    if (namedColorList != NULL) {
        // Call the function-under-test
        result = cmsNamedColorCount(namedColorList);

        // Clean up
        cmsFreeNamedColorList(namedColorList);
    }

    cmsDeleteContext(contextID);

    return 0;
}