#include <stdint.h>
#include <lcms2.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    cmsContext context;
    cmsColorSpaceSignature colorSpace;
    cmsToneCurve *toneCurve;
    const cmsToneCurve **toneCurves;

    // Initialize context
    context = cmsCreateContext(NULL, NULL);

    // Ensure size is sufficient for our needs
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Initialize colorSpace from the input data
    colorSpace = *(cmsColorSpaceSignature *)data;

    // Allocate memory for toneCurves and initialize a single toneCurve
    toneCurves = (const cmsToneCurve **)malloc(sizeof(cmsToneCurve *));
    if (toneCurves == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a tone curve
    toneCurve = cmsBuildGamma(context, 2.2); // Using a gamma value of 2.2 as an example
    toneCurves[0] = toneCurve;

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLinearizationDeviceLinkTHR(context, colorSpace, toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    cmsFreeToneCurve(toneCurve);
    free(toneCurves);
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

    LLVMFuzzerTestOneInput_4(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
