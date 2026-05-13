#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_444(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsHPROFILE profiles[2];
    cmsUInt32Number nProfiles = 2;
    cmsUInt32Number inputFormat = TYPE_RGB_8;  // Assuming RGB 8-bit format
    cmsUInt32Number outputFormat = TYPE_RGB_8; // Assuming RGB 8-bit format
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number flags = 0;

    // Create dummy profiles for testing
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreate_sRGBProfile();

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransform(
        profiles, nProfiles, inputFormat, outputFormat, intent, flags);

    // Clean up
    if (transform != NULL) {
        cmsDeleteTransform(transform);
    }
    cmsCloseProfile(profiles[0]);
    cmsCloseProfile(profiles[1]);

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

    LLVMFuzzerTestOneInput_444(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
