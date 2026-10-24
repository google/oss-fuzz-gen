#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "lcms2.h"

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    cmsStage *stage = NULL;
    cmsPipeline *pipeline = NULL;
    cmsContext contextID;

    // We need at least some data to create a stage
    if (size < 1) {
        return 0;
    }

    // Create a dummy pipeline to hold the stage
    pipeline = cmsPipelineAlloc(NULL, 1, 1);
    if (pipeline == NULL) {
        return 0;
    }

    // Use the input data to create a stage
    // For demonstration, let's assume the first byte determines the type of stage
    switch (data[0] % 3) {
        case 0:
            // Create an identity stage
            stage = cmsStageAllocIdentity(NULL, 1);
            break;
        case 1:
            // Create a tone curve stage with some dummy curve
            {
                cmsToneCurve *curve = cmsBuildGamma(NULL, 2.2);
                if (curve != NULL) {
                    stage = cmsStageAllocToneCurves(NULL, 1, &curve);
                    cmsFreeToneCurve(curve);
                }
            }
            break;
        case 2:
            // Create a matrix stage with some dummy matrix
            {
                cmsFloat64Number matrix[3][3] = {
                    {1.0, 0.0, 0.0},
                    {0.0, 1.0, 0.0},
                    {0.0, 0.0, 1.0}
                };
                cmsFloat64Number offset[3] = {0.0, 0.0, 0.0};
                stage = cmsStageAllocMatrix(NULL, 3, 3, &matrix[0][0], offset);
            }
            break;
    }

    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Add the stage to the pipeline
    if (!cmsPipelineInsertStage(pipeline, cmsAT_BEGIN, stage)) {
        cmsStageFree(stage);
        cmsPipelineFree(pipeline);
        return 0;
    }

    // Call the function-under-test
    contextID = cmsGetStageContextID(stage);

    // Free allocated memory
    cmsPipelineFree(pipeline);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
