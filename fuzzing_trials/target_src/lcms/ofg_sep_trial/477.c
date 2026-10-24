#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_477(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract parameters
    if (size < sizeof(cmsUInt32Number) * 4 + sizeof(cmsFloat64Number) * 4) {
        return 0; // Not enough data to proceed
    }

    // Extract parameters from the input data
    cmsUInt32Number n = *((cmsUInt32Number*)data);
    cmsFloat64Number a = *((cmsFloat64Number*)(data + sizeof(cmsUInt32Number)));
    cmsFloat64Number b = *((cmsFloat64Number*)(data + sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)));
    cmsFloat64Number c = *((cmsFloat64Number*)(data + sizeof(cmsUInt32Number) + 2 * sizeof(cmsFloat64Number)));
    cmsFloat64Number d = *((cmsFloat64Number*)(data + sizeof(cmsUInt32Number) + 3 * sizeof(cmsFloat64Number)));
    cmsUInt32Number e = *((cmsUInt32Number*)(data + sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number)));
    cmsUInt32Number f = *((cmsUInt32Number*)(data + 2 * sizeof(cmsUInt32Number) + 4 * sizeof(cmsFloat64Number)));

    // Use a valid non-NULL context
    cmsContext context = cmsCreateContext(NULL, NULL);

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateBCHSWabstractProfileTHR(context, n, a, b, c, d, e, f);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    cmsDeleteContext(context);

    return 0;
}