#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    cmsContext context = (cmsContext)0x1; // Dummy non-null context
    cmsCIExyY whitePoint = {0.3127, 0.3290, 1.0}; // D65 standard illuminant
    cmsCIExyYTRIPLE primaries = {
        {0.64, 0.33, 1.0}, // Red primary
        {0.30, 0.60, 1.0}, // Green primary
        {0.15, 0.06, 1.0}  // Blue primary
    };

    // Allocate memory for tone curves
    cmsToneCurve *toneCurves[3];
    for (int i = 0; i < 3; i++) {
        toneCurves[i] = cmsBuildGamma(context, 2.2); // Simple gamma curve
        if (toneCurves[i] == NULL) {
            for (int j = 0; j < i; j++) {
                cmsFreeToneCurve(toneCurves[j]);
            }
            return 0;
        }
    }

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, (const cmsToneCurve **)toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(toneCurves[i]);
    }

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

    LLVMFuzzerTestOneInput_83(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
