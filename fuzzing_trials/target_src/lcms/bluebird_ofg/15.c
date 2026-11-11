#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "lcms2.h"

// Define a simple log error handler function
void myLogErrorHandler_15(cmsContext contextID, cmsUInt32Number ErrorCode, const char *Text) {
    // Do nothing, just a placeholder for the fuzzing
}

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Call the function-under-test with a non-NULL error handler
    cmsSetLogErrorHandler(myLogErrorHandler_15);

    // Check if the size is sufficient to create a profile
    if (size < sizeof(cmsHPROFILE)) {
        return 0;
    }

    // Create a profile from the input data
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, size);
    if (hProfile == NULL) {
        return 0; // If profile creation fails, exit early
    }

    // Perform a simple operation using the profile

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromMem to cmsSetHeaderModel
    cmsFloat64Number ret_cmsDetectTAC_scuxn = cmsDetectTAC(hProfile);
    if (ret_cmsDetectTAC_scuxn < 0){
    	return 0;
    }
    cmsSetHeaderModel(hProfile, (unsigned long )ret_cmsDetectTAC_scuxn);
    // End mutation: Producer.APPEND_MUTATOR
    
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (hTransform != NULL) {
        uint8_t sample[3] = {0, 0, 0};
        cmsDoTransform(hTransform, sample, sample, 1);
        cmsDeleteTransform(hTransform);
    }

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
