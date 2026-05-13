#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_219(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    cmsContext context = (cmsContext)0x1; // Non-NULL context
    cmsColorSpaceSignature colorSpace;
    cmsFloat64Number limit;

    // Ensure size is sufficient to extract parameters
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Extract parameters from data
    colorSpace = *(cmsColorSpaceSignature *)data;
    limit = *(cmsFloat64Number *)(data + sizeof(cmsColorSpaceSignature));

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateInkLimitingDeviceLinkTHR(context, colorSpace, limit);

    // Clean up if necessary
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}