#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_273(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract necessary data
    if (size < sizeof(cmsColorSpaceSignature)) {
        return 0;
    }

    // Extract cmsColorSpaceSignature from the input data
    cmsColorSpaceSignature colorSpaceSignature = *(cmsColorSpaceSignature *)data;

    // Create a dummy cmsToneCurve array
    cmsToneCurve *toneCurves[3];
    toneCurves[0] = cmsBuildGamma(NULL, 2.2); // Example gamma value
    toneCurves[1] = cmsBuildGamma(NULL, 2.2);
    toneCurves[2] = cmsBuildGamma(NULL, 2.2);

    // Call the function-under-test
    cmsHPROFILE profile = cmsCreateLinearizationDeviceLink(colorSpaceSignature, (const cmsToneCurve **)toneCurves);

    // Clean up
    if (profile != NULL) {
        cmsCloseProfile(profile);
    }

    for (int i = 0; i < 3; i++) {
        if (toneCurves[i] != NULL) {
            cmsFreeToneCurve(toneCurves[i]);
        }
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

    LLVMFuzzerTestOneInput_273(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
