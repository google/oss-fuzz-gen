#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_483(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsContext context = (cmsContext)data; // Using data as a dummy context
    cmsUInt32Number nColors = 10; // Arbitrary non-zero number of colors
    cmsUInt32Number flags = 0; // Flags set to 0 for simplicity

    // Ensure the size is sufficient for non-NULL strings
    const char *prefix = "Prefix"; // Non-NULL prefix string
    const char *suffix = "Suffix"; // Non-NULL suffix string

    if (size < sizeof(cmsContext)) {
        return 0; // Not enough data to proceed
    }

    // Call the function-under-test
    cmsNAMEDCOLORLIST *namedColorList = cmsAllocNamedColorList(context, nColors, flags, prefix, suffix);

    // Free the allocated named color list if it was successfully created
    if (namedColorList != NULL) {
        cmsFreeNamedColorList(namedColorList);
    }

    return 0;
}