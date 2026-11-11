// This fuzz driver is generated for library lcms, aiming to fuzz the following functions:
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsPipelineFree at cmslut.c:1427:16 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:399:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:399:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:399:19 in lcms2.h
// cmsDetectDestinationBlackPoint at cmssamp.c:399:19 in lcms2.h
// cmsDetectTAC at cmsgmt.c:462:28 in lcms2.h
// cmsCloseProfile at cmsio0.c:1668:20 in lcms2.h
// cmsCreate_sRGBProfile at cmsvirt.c:680:23 in lcms2.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <lcms2.h>

static cmsHPROFILE createDummyProfile() {
    // Instead of manually allocating memory, use lcms to create a valid profile
    cmsHPROFILE hProfile = cmsCreate_sRGBProfile();
    return hProfile;
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    // Prepare dummy pipeline for cmsPipelineFree
    cmsPipeline* pipeline = NULL; // Cannot instantiate due to incomplete type

    // Attempt to free a NULL pipeline multiple times
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);
    cmsPipelineFree(pipeline);

    // Prepare dummy profile for cmsDetectDestinationBlackPoint and cmsDetectTAC
    cmsHPROFILE hProfile = createDummyProfile();
    if (hProfile) {
        cmsCIEXYZ blackPoint;
        cmsDetectDestinationBlackPoint(&blackPoint, hProfile, 0, 0);
        cmsDetectDestinationBlackPoint(&blackPoint, hProfile, 1, 0);
        cmsDetectDestinationBlackPoint(&blackPoint, hProfile, 2, 0);
        cmsDetectDestinationBlackPoint(&blackPoint, hProfile, 3, 0);

        cmsDetectTAC(hProfile);

        cmsCloseProfile(hProfile); // Properly close the profile
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
