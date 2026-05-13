#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for the required parameters
    if (size < sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize the parameters
    cmsHTRANSFORM hTransform;
    cmsFloat64Number version;
    cmsUInt32Number flags;

    // Extract values from the input data
    version = *(cmsFloat64Number *)data;
    flags = *(cmsUInt32Number *)(data + sizeof(cmsFloat64Number));

    // Create a dummy transform for testing
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    hTransform = cmsCreateTransform(hProfile, TYPE_RGB_8, hProfile, TYPE_RGB_8, INTENT_PERCEPTUAL, 0);
    if (hTransform == NULL) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE deviceLinkProfile = cmsTransform2DeviceLink(hTransform, version, flags);

    // Clean up
    if (deviceLinkProfile != NULL) {
        cmsCloseProfile(deviceLinkProfile);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_213(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
