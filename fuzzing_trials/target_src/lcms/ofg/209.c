#include <stdint.h>
#include <stddef.h>
#include <lcms2.h>
#include "/src/lcms/include/lcms2.h"

// Ensure that the necessary macro is defined for the function to be available
#define CMS_USE_LCMS2_INTERNALS

int LLVMFuzzerTestOneInput_209(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to populate a cmsCIELab structure
    if (size < sizeof(float) * 3) {
        return 0;
    }

    // Initialize a cmsCIELab structure with the provided data
    cmsCIELab lab;
    const float *data_as_float = (const float *)data;
    lab.L = data_as_float[0];
    lab.a = data_as_float[1];
    lab.b = data_as_float[2];

    // Create a cmsHANDLE, which in this context could be a placeholder for a real handle
    cmsContext handle = cmsCreateContext(NULL, NULL);
    if (handle == NULL) {
        return 0;
    }

    // Call the function-under-test with a valid cmsHANDLE and cmsCIELab structure
    cmsHPROFILE hProfile = cmsCreateLab4Profile(NULL);
    if (hProfile == NULL) {
        cmsDeleteContext(handle);
        return 0;
    }

    cmsPipeline *pipeline = cmsPipelineAlloc(handle, 3, 3);
    if (pipeline == NULL) {
        cmsCloseProfile(hProfile);
        cmsDeleteContext(handle);
        return 0;
    }

    // Instead of using cmsStageAllocLabV2ToLabV4, use a known stage allocation function
    cmsStage *stage = cmsStageAllocIdentity(handle, 3);
    if (stage == NULL) {
        cmsPipelineFree(pipeline);
        cmsCloseProfile(hProfile);
        cmsDeleteContext(handle);
        return 0;
    }

    cmsBool result = cmsPipelineInsertStage(pipeline, cmsAT_END, stage);
    if (!result) {
        cmsPipelineFree(pipeline);
        cmsCloseProfile(hProfile);
        cmsDeleteContext(handle);
        return 0;
    }

    // Ensure the lab values are within the expected range before adding the point
    if (lab.L >= 0 && lab.L <= 100 && lab.a >= -128 && lab.a <= 127 && lab.b >= -128 && lab.b <= 127) {
        // Attempt to add the point to the grid
        result = cmsGDBAddPoint(pipeline, &lab);
    }

    // Clean up resources
    cmsPipelineFree(pipeline);
    cmsCloseProfile(hProfile);
    cmsDeleteContext(handle);

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

    LLVMFuzzerTestOneInput_209(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
