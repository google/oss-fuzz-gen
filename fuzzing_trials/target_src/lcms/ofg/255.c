#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    cmsContext context = NULL; // Using NULL for default context
    cmsUInt32Number intent = 0; // Rendering intent
    cmsUInt32Number flags = 0; // Flags for the transform
    cmsUInt32Number inputFormat = TYPE_RGB_8; // Input format
    cmsUInt32Number outputFormat = TYPE_RGB_8; // Output format
    cmsUInt32Number nProfiles = 2; // Number of profiles

    // Allocate memory for profiles
    cmsHPROFILE *profiles = (cmsHPROFILE *)malloc(nProfiles * sizeof(cmsHPROFILE));
    if (!profiles) {
        return 0; // Memory allocation failed
    }

    // Create dummy profiles for testing
    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        profiles[i] = cmsCreate_sRGBProfile();
        if (!profiles[i]) {
            // Clean up and exit if profile creation fails
            for (cmsUInt32Number j = 0; j < i; j++) {
                cmsCloseProfile(profiles[j]);
            }
            free(profiles);
            return 0;
        }
    }

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateMultiprofileTransformTHR(
        context, profiles, nProfiles, inputFormat, outputFormat, intent, flags);

    // Clean up
    if (transform) {
        cmsDeleteTransform(transform);
    }

    for (cmsUInt32Number i = 0; i < nProfiles; i++) {
        cmsCloseProfile(profiles[i]);
    }
    free(profiles);

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

    LLVMFuzzerTestOneInput_255(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
