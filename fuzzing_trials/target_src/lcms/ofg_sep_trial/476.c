#include <stdint.h>
#include <lcms2.h>
#include <string.h>

int LLVMFuzzerTestOneInput_476(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract necessary parameters
    if (size < sizeof(cmsFloat64Number) * 4 + sizeof(cmsUInt32Number) * 2) {
        return 0; // Not enough data to proceed
    }

    // Extract parameters from the input data
    cmsContext context = (cmsContext)0x1;  // Dummy non-NULL context
    cmsUInt32Number dwFlags = 0;
    
    cmsFloat64Number L, a, b, c;
    cmsUInt32Number nGridPoints, dwType;

    // Copy data into variables
    memcpy(&L, data, sizeof(cmsFloat64Number));
    memcpy(&a, data + sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));
    memcpy(&b, data + 2 * sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));
    memcpy(&c, data + 3 * sizeof(cmsFloat64Number), sizeof(cmsFloat64Number));
    memcpy(&nGridPoints, data + 4 * sizeof(cmsFloat64Number), sizeof(cmsUInt32Number));
    memcpy(&dwType, data + 4 * sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number), sizeof(cmsUInt32Number));

    // Call the function-under-test with fuzzed parameters
    cmsHPROFILE profile = cmsCreateBCHSWabstractProfileTHR(context, dwFlags, L, a, b, c, nGridPoints, dwType);

    // Clean up if a profile was created
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    return 0;
}