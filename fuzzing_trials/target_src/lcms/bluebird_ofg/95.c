#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    cmsCIEXYZ blackPoint;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent = 0;
    cmsUInt32Number flags = 0;

    // Initialize blackPoint with some non-NULL values
    blackPoint.X = 0.0;
    blackPoint.Y = 0.0;
    blackPoint.Z = 0.0;

    // Create a profile from memory if possible
    if (size > 0) {
        hProfile = cmsOpenProfileFromMem(data, size);
        if (hProfile == NULL) {
            return 0; // Exit if profile creation fails
        }
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromMem to cmsSetColorSpace
        cmsColorSpaceSignature ret__cmsICCcolorSpace_cjfys = _cmsICCcolorSpace(PT_Lab);
        cmsSetColorSpace(hProfile, ret__cmsICCcolorSpace_cjfys);
        // End mutation: Producer.APPEND_MUTATOR
        
} else {
        return 0; // Exit if size is zero
    }

    // Call the function-under-test
    cmsBool result = cmsDetectDestinationBlackPoint(&blackPoint, hProfile, intent, flags);

    // Close the profile
    cmsCloseProfile(hProfile);

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
