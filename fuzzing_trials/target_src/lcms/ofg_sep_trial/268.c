#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy
#include <lcms2.h>

int LLVMFuzzerTestOneInput_268(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read from
    if (size < sizeof(cmsViewingConditions)) {
        return 0;
    }

    // Initialize a cmsContext
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Create a cmsViewingConditions structure and populate it with data
    cmsViewingConditions viewingConditions;
    memcpy(&viewingConditions, data, sizeof(cmsViewingConditions));

    // Call the function-under-test
    cmsHANDLE handle = cmsCIECAM02Init(context, &viewingConditions);

    // Clean up
    if (handle != NULL) {
        cmsCIECAM02Done(handle);
    }
    cmsDeleteContext(context);

    return 0;
}