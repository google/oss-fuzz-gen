#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_231(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to derive a gamma value
    }

    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number numCurves = 1; // We will test with a single tone curve for simplicity

    // Allocate memory for the tone curve pointers
    const cmsToneCurve **toneCurves = (const cmsToneCurve **)malloc(numCurves * sizeof(cmsToneCurve *));
    if (toneCurves == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Derive a gamma value from the input data
    double gamma = 1.0 + (data[0] / 255.0) * 3.0; // Map input byte to a gamma range of [1.0, 4.0]

    // Create a tone curve from the input-derived gamma value
    cmsToneCurve *curve = cmsBuildGamma(context, gamma);
    if (curve == NULL) {
        free(toneCurves);
        cmsDeleteContext(context);
        return 0;
    }
    toneCurves[0] = curve;

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocToneCurves(context, numCurves, toneCurves);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }
    cmsFreeToneCurve(curve);
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

    LLVMFuzzerTestOneInput_231(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
