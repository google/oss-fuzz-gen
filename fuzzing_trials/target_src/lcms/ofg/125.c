#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <lcms2.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_125(const uint8_t *data, size_t size) {
    // Ensure there is enough data for cmsDetectBlackPoint parameters
    if (size < sizeof(cmsUInt32Number) * 2 + sizeof(cmsCIEXYZ)) {
        return 0;
    }

    // Initialize parameters for cmsDetectBlackPoint
    cmsCIEXYZ blackPoint;
    cmsHPROFILE hProfile;
    cmsUInt32Number intent;
    cmsUInt32Number flags;

    // Extract cmsCIEXYZ from data
    memcpy(&blackPoint, data, sizeof(cmsCIEXYZ));
    data += sizeof(cmsCIEXYZ);
    size -= sizeof(cmsCIEXYZ);

    // Create a dummy profile for testing
    hProfile = cmsCreate_sRGBProfile();

    // Extract cmsUInt32Number values from data
    memcpy(&intent, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    memcpy(&flags, data, sizeof(cmsUInt32Number));
    data += sizeof(cmsUInt32Number);
    size -= sizeof(cmsUInt32Number);

    // Call the function-under-test
    cmsBool result = cmsDetectBlackPoint(&blackPoint, hProfile, intent, flags);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_125(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
