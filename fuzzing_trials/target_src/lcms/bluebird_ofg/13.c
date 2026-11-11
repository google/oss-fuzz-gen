#include <sys/stat.h>
#include <stdint.h>
#include <string.h>  // For memcpy
#include "lcms2.h"

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the necessary parameters
    if (size < sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Extract cmsFloat64Number and cmsUInt32Number from data
    cmsFloat64Number float64Param;
    cmsUInt32Number uint32Param;

    // Copy data to the variables
    memcpy(&float64Param, data, sizeof(cmsFloat64Number));
    memcpy(&uint32Param, data + sizeof(cmsFloat64Number), sizeof(cmsUInt32Number));

    // Initialize a dummy cmsHTRANSFORM for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    cmsHTRANSFORM hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);

    // Call the function-under-test
    cmsHPROFILE resultProfile = cmsTransform2DeviceLink(hTransform, float64Param, uint32Param);

    // Clean up
    if (resultProfile != NULL) {
        cmsCloseProfile(resultProfile);
    }
    cmsDeleteTransform(hTransform);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
