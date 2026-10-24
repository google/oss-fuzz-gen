#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_243(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    // Ensure we have enough data to work with
    if (size < sizeof(cmsHPROFILE) * 2 + sizeof(cmsUInt32Number) * 4) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize profiles
    cmsHPROFILE profiles[2];
    for (int i = 0; i < 2; i++) {
        profiles[i] = cmsOpenProfileFromMem(data, size);
        if (profiles[i] == NULL) {
            for (int j = 0; j < i; j++) {
                cmsCloseProfile(profiles[j]);
            }
            cmsDeleteContext(context);
            return 0;
        }
    }

    // Extract cmsUInt32Number values from data
    cmsUInt32Number intent = *(const cmsUInt32Number *)(data + sizeof(cmsHPROFILE) * 2);
    cmsUInt32Number inputFormat = *(const cmsUInt32Number *)(data + sizeof(cmsHPROFILE) * 2 + sizeof(cmsUInt32Number));
    cmsUInt32Number outputFormat = *(const cmsUInt32Number *)(data + sizeof(cmsHPROFILE) * 2 + sizeof(cmsUInt32Number) * 2);
    cmsUInt32Number dwFlags = *(const cmsUInt32Number *)(data + sizeof(cmsHPROFILE) * 2 + sizeof(cmsUInt32Number) * 3);

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransformTHR(context, profiles, 2, inputFormat, outputFormat, intent, dwFlags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }

    for (int i = 0; i < 2; i++) {
        cmsCloseProfile(profiles[i]);
    }

    cmsDeleteContext(context);

    return 0;
}