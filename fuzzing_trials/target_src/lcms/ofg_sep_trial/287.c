#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

// Remove the 'extern "C"' linkage specification, as it is not needed in C
int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsFloat64Number adaptationState;

    // Ensure size is sufficient to extract cmsFloat64Number
    if (size < sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize context
    context = cmsCreateContext(NULL, NULL);

    // Extract a cmsFloat64Number from the data
    adaptationState = *((cmsFloat64Number*)data);

    // Call the function-under-test
    cmsFloat64Number result = cmsSetAdaptationStateTHR(context, adaptationState);

    // Clean up
    cmsDeleteContext(context);

    return 0;
}