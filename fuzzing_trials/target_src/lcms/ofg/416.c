#include <stdint.h>
#include <stdlib.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_416(const uint8_t *data, size_t size) {
    if (size < 6) {
        // We need at least 6 bytes to extract 3 floats for the tone curves
        return 0;
    }

    cmsPipeline *pipeline1 = cmsPipelineAlloc(NULL, 3, 3);
    cmsPipeline *pipeline2 = cmsPipelineAlloc(NULL, 3, 3);

    if (pipeline1 == NULL || pipeline2 == NULL) {
        if (pipeline1 != NULL) cmsPipelineFree(pipeline1);
        if (pipeline2 != NULL) cmsPipelineFree(pipeline2);
        return 0;
    }

    // Use input data to create tone curves
    float gamma1 = ((data[0] << 8) | data[1]) / 256.0;
    float gamma2 = ((data[2] << 8) | data[3]) / 256.0;
    float gamma3 = ((data[4] << 8) | data[5]) / 256.0;

    cmsToneCurve *toneCurves1[3] = {cmsBuildGamma(NULL, gamma1), cmsBuildGamma(NULL, gamma2), cmsBuildGamma(NULL, gamma3)};
    cmsToneCurve *toneCurves2[3] = {cmsBuildGamma(NULL, gamma1), cmsBuildGamma(NULL, gamma2), cmsBuildGamma(NULL, gamma3)};
    cmsStage *stage1 = cmsStageAllocToneCurves(NULL, 3, toneCurves1);
    cmsStage *stage2 = cmsStageAllocToneCurves(NULL, 3, toneCurves2);

    if (stage1 != NULL && stage2 != NULL) {
        cmsPipelineInsertStage(pipeline1, cmsAT_BEGIN, stage1);
        cmsPipelineInsertStage(pipeline2, cmsAT_BEGIN, stage2);
    }

    // Call the function-under-test
    cmsBool result = cmsPipelineCat(pipeline1, pipeline2);

    // Clean up
    cmsPipelineFree(pipeline1);
    cmsPipelineFree(pipeline2);

    for (int i = 0; i < 3; i++) {
        cmsFreeToneCurve(toneCurves1[i]);
        cmsFreeToneCurve(toneCurves2[i]);
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

    LLVMFuzzerTestOneInput_416(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
