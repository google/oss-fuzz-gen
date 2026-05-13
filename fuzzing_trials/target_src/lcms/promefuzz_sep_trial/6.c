// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineFree at cmslut.c:1426:16 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:355:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:355:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:355:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:355:19 in lcms2.h
// cmsDetectTAC at cmsgmt.c:462:28 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
// cmsCloseProfile at cmsio0.c:1585:20 in lcms2.h
// cmsPipelineAlloc at cmslut.c:1377:24 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "lcms2.h"

static cmsPipeline* createDummyPipeline() {
    // Allocate a cmsPipeline structure with fake elements for testing
    cmsPipeline* pipeline = cmsPipelineAlloc(NULL, 0, 0);
    return pipeline;
}

static void fuzzPipelineFree() {
    cmsPipeline* pipelines[12];
    for (int i = 0; i < 12; i++) {
        pipelines[i] = createDummyPipeline();
        if (pipelines[i]) {
            cmsPipelineFree(pipelines[i]);
        }
    }
}

static void fuzzDetectDestinationBlackPoint(cmsHPROFILE profile) {
    cmsCIEXYZ blackPoint;
    cmsDetectDestinationBlackPoint(&blackPoint, profile, 0, 0);
    cmsDetectDestinationBlackPoint(&blackPoint, profile, 1, 0);
    cmsDetectDestinationBlackPoint(&blackPoint, profile, 2, 0);
    cmsDetectDestinationBlackPoint(&blackPoint, profile, 3, 0);
}

static void fuzzDetectTAC(cmsHPROFILE profile) {
    cmsDetectTAC(profile);
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    cmsHPROFILE profile = cmsCreate_sRGBProfile();
    if (!profile) return 0;

    fuzzPipelineFree();
    fuzzDetectDestinationBlackPoint(profile);
    fuzzDetectTAC(profile);

    cmsCloseProfile(profile);
    return 0;
}