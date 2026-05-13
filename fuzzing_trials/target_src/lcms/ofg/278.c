#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_278(const uint8_t *data, size_t size) {
    if (size < 128) {
        // Not enough data to create a profile
        return 0;
    }

    // Declare and initialize all necessary variables
    cmsContext context = NULL; // Assuming a null context for simplicity
    cmsUInt32Number nProfiles = 2; // Number of profiles
    cmsHPROFILE profiles[2];
    cmsBool bInput[2] = {TRUE, FALSE}; // Boolean array for input/output
    cmsUInt32Number intents[2] = {INTENT_PERCEPTUAL, INTENT_RELATIVE_COLORIMETRIC};
    cmsFloat64Number adapt[2] = {1.0, 0.0}; // Adaptation states
    cmsHPROFILE hProof = NULL; // Assuming no proofing profile
    cmsUInt32Number intent = INTENT_PERCEPTUAL;
    cmsUInt32Number dwFlags = 0; // Flags for the transform
    cmsUInt32Number dwPrecalcMode = 0; // Precalculation mode
    cmsUInt32Number dwRenderingIntent = 0; // Rendering intent

    // Create profiles from input data
    profiles[0] = cmsOpenProfileFromMem(data, size / 2);
    profiles[1] = cmsOpenProfileFromMem(data + size / 2, size / 2);

    if (profiles[0] == NULL || profiles[1] == NULL) {
        if (profiles[0] != NULL) cmsCloseProfile(profiles[0]);
        if (profiles[1] != NULL) cmsCloseProfile(profiles[1]);
        return 0;
    }

    // Call the function-under-test
    cmsHTRANSFORM transform = cmsCreateExtendedTransform(
        context,
        nProfiles,
        profiles,
        bInput,
        intents,
        adapt,
        hProof,
        intent,
        dwFlags,
        dwPrecalcMode,
        dwRenderingIntent
    );

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

    LLVMFuzzerTestOneInput_278(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
