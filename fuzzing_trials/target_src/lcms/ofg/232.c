#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_232(const uint8_t *data, size_t size) {
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsUInt32Number nCurves = 2; // Example number of tone curves

    // Allocate memory for tone curves
    const cmsToneCurve **toneCurves = (const cmsToneCurve **)malloc(nCurves * sizeof(cmsToneCurve *));
    if (toneCurves == NULL) {
        cmsDeleteContext(context);
        return 0;
    }

    // Initialize tone curves with some default values
    for (cmsUInt32Number i = 0; i < nCurves; i++) {
        toneCurves[i] = cmsBuildGamma(context, 2.2); // Example gamma value
        if (toneCurves[i] == NULL) {
            for (cmsUInt32Number j = 0; j < i; j++) {
                cmsFreeToneCurve(toneCurves[j]);
            }
            free(toneCurves);
            cmsDeleteContext(context);
            return 0;
        }
    }

    // Call the function-under-test
    cmsStage *stage = cmsStageAllocToneCurves(context, nCurves, toneCurves);

    // Clean up
    if (stage != NULL) {
        cmsStageFree(stage);
    }

    for (cmsUInt32Number i = 0; i < nCurves; i++) {
        cmsFreeToneCurve((cmsToneCurve *)toneCurves[i]);
    }
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

    LLVMFuzzerTestOneInput_232(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
