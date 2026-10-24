#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_286(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsFloat64Number adaptationState = 1.0; // Default adaptation state

    // Ensure size is sufficient to extract a cmsFloat64Number
    if (size >= sizeof(cmsFloat64Number)) {
        // Copy data into adaptationState, ensuring proper type casting
        adaptationState = *((cmsFloat64Number*)data);
    }

    // Call the function-under-test
    cmsFloat64Number result = cmsSetAdaptationStateTHR(context, adaptationState);

    // Clean up
    cmsDeleteContext(context);

    return 0;
}