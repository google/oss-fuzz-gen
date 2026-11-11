#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsCIEXYZ blackPoint;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    // Ensure size is sufficient to extract needed values
    if (size < sizeof(cmsCIEXYZ) + 2 * sizeof(cmsUInt32Number)) {
        return 0;
    }

    // Initialize blackPoint from data
    blackPoint.X = *(cmsFloat64Number *)(data);
    blackPoint.Y = *(cmsFloat64Number *)(data + sizeof(cmsFloat64Number));
    blackPoint.Z = *(cmsFloat64Number *)(data + 2 * sizeof(cmsFloat64Number));

    // Initialize intent and flags from data
    intent = *(cmsUInt32Number *)(data + 3 * sizeof(cmsFloat64Number));
    flags = *(cmsUInt32Number *)(data + 3 * sizeof(cmsFloat64Number) + sizeof(cmsUInt32Number));

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();
    if (hProfile == NULL) {
        return 0;
    }

    // Call the function-under-test
    cmsBool result = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);

    // Clean up
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

    LLVMFuzzerTestOneInput_124(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
