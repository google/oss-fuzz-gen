#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (context == NULL) {
        return 0;
    }

    cmsCIExyY whitePoint;
    cmsCIExyYTRIPLE primaries;
    cmsToneCurve *toneCurves[3];

    // Initialize whitePoint with some default values
    whitePoint.x = 0.3127;
    whitePoint.y = 0.3290;
    whitePoint.Y = 1.0;

    // Initialize primaries with some default values
    primaries.Red.x = 0.64;
    primaries.Red.y = 0.33;
    primaries.Red.Y = 1.0;
    primaries.Green.x = 0.30;
    primaries.Green.y = 0.60;
    primaries.Green.Y = 1.0;
    primaries.Blue.x = 0.15;
    primaries.Blue.y = 0.06;
    primaries.Blue.Y = 1.0;

    // Create tone curves
    toneCurves[0] = cmsBuildGamma(context, 2.2);
    toneCurves[1] = cmsBuildGamma(context, 2.2);
    toneCurves[2] = cmsBuildGamma(context, 2.2);

    if (toneCurves[0] == NULL || toneCurves[1] == NULL || toneCurves[2] == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, (const cmsToneCurve **)toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsFreeToneCurve(toneCurves[0]);
    cmsFreeToneCurve(toneCurves[1]);
    cmsFreeToneCurve(toneCurves[2]);
    cmsDeleteContext(context);

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

    LLVMFuzzerTestOneInput_84(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
