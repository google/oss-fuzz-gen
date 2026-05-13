#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_359(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsNAMEDCOLORLIST *namedColorList;
    cmsUInt32Number index;
    char name[256];
    char prefix[256];
    char suffix[256];
    cmsUInt16Number PCS[3];
    cmsUInt16Number deviceColorant[3];

    // Ensure the data size is sufficient
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Create a named color list for testing
    namedColorList = cmsAllocNamedColorList(NULL, 1, 32, "Prefix", "Suffix");
    if (namedColorList == NULL) {
        return 0;
    }

    // Set a dummy named color
    cmsNamedColorInfo(namedColorList, 0, "ColorName", "Prefix", "Suffix", PCS, deviceColorant);

    // Extract the index from the data
    index = *(cmsUInt32Number *)data;

    // Call the function-under-test
    cmsBool result = cmsNamedColorInfo(namedColorList, index, name, prefix, suffix, PCS, deviceColorant);

    // Clean up
    cmsFreeNamedColorList(namedColorList);

    return 0;
}