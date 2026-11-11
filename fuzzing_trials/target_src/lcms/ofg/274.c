#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_274(const uint8_t *data, size_t size) {
    // Define variables
    cmsColorSpaceSignature colorSpace;
    cmsToneCurve* toneCurves[1];
    cmsToneCurve* toneCurve;
    cmsHPROFILE profile;

    // Ensure size is sufficient for our needs
    if (size < sizeof(cmsColorSpaceSignature) + sizeof(double)) {
        return 0;
    }

    // Initialize colorSpace from data
    colorSpace = *(cmsColorSpaceSignature*)data;

    // Initialize a tone curve
    double gamma = *((double*)(data + sizeof(cmsColorSpaceSignature)));
    toneCurve = cmsBuildGamma(NULL, gamma);
    toneCurves[0] = toneCurve;

    // Call the function-under-test
    profile = cmsCreateLinearizationDeviceLink(colorSpace, (const cmsToneCurve**)toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }
    if (toneCurve != NULL) {
        cmsFreeToneCurve(toneCurve);
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

    LLVMFuzzerTestOneInput_274(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
