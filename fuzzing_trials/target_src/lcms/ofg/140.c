#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_140(const uint8_t *data, size_t size) {
    cmsHTRANSFORM transform;
    cmsHPROFILE inputProfile, outputProfile;
    cmsUInt32Number inputFormat, outputFormat;
    cmsUInt32Number intent = INTENT_PERCEPTUAL; // Using a standard rendering intent
    cmsUInt32Number flags = 0; // No special flags

    // Check if the size is sufficient to create profiles
    if (size < 2) {
        return 0;
    }

    // Create input and output profiles from data
    inputProfile = cmsOpenProfileFromMem(data, size / 2);
    outputProfile = cmsOpenProfileFromMem(data + size / 2, size / 2);

    // Ensure profiles are created successfully
    if (inputProfile == NULL || outputProfile == NULL) {
        if (inputProfile) cmsCloseProfile(inputProfile);
        if (outputProfile) cmsCloseProfile(outputProfile);
        return 0;
    }

    // Create a transform
    transform = cmsCreateTransform(inputProfile, TYPE_RGB_8, outputProfile, TYPE_RGB_8, intent, flags);

    // Ensure transform is created successfully
    if (transform != NULL) {
        // Call the function-under-test
        inputFormat = cmsGetTransformInputFormat(transform);

        // Clean up
        cmsDeleteTransform(transform);
    }

    // Close profiles
    cmsCloseProfile(inputProfile);
    cmsCloseProfile(outputProfile);

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

    LLVMFuzzerTestOneInput_140(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
