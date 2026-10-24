#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_458(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    cmsHPROFILE profile = cmsCreateXYZProfileTHR(context);
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    cmsDeleteContext(context);
    return 0;
}