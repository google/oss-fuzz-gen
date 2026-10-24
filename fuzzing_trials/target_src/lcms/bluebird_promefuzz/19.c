#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include "lcms2.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        return 0;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromFile to cmsDetectRGBProfileGamma

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromFile to cmsGetPostScriptColorResource
    cmsContext ret_cmsGetProfileContextID_jdpzv = cmsGetProfileContextID(hProfile);
    cmsFloat64Number ret_cmsSetAdaptationState_vjhas = cmsSetAdaptationState(LCMS_USED_AS_INPUT);
    if (ret_cmsSetAdaptationState_vjhas < 0){
    	return 0;
    }
    cmsUInt32Number ret_cmsGetTransformOutputFormat_nobfd = cmsGetTransformOutputFormat(0);
    if (ret_cmsGetTransformOutputFormat_nobfd < 0){
    	return 0;
    }
    cmsIOHANDLER* ret_cmsGetProfileIOhandler_juqsa = cmsGetProfileIOhandler(hProfile);
    if (ret_cmsGetProfileIOhandler_juqsa == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cmsGetProfileIOhandler_juqsa) {
    	return 0;
    }
    cmsUInt32Number ret_cmsGetPostScriptColorResource_eqlra = cmsGetPostScriptColorResource(ret_cmsGetProfileContextID_jdpzv, 0, hProfile, (unsigned long )ret_cmsSetAdaptationState_vjhas, ret_cmsGetTransformOutputFormat_nobfd, ret_cmsGetProfileIOhandler_juqsa);
    if (ret_cmsGetPostScriptColorResource_eqlra < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsGetPostScriptColorResource to cmsStageAllocCLutFloat
    cmsUInt32Number ret_cmsGetTransformInputFormat_hvllo = cmsGetTransformInputFormat(0);
    if (ret_cmsGetTransformInputFormat_hvllo < 0){
    	return 0;
    }
    cmsBool ret_cmsPlugin_esmdj = cmsPlugin(NULL);
    if (ret_cmsPlugin_esmdj < 0){
    	return 0;
    }
    cmsStage* ret_cmsStageAllocCLutFloat_zekwi = cmsStageAllocCLutFloat(ret_cmsGetProfileContextID_jdpzv, ret_cmsGetTransformOutputFormat_nobfd, ret_cmsGetTransformInputFormat_hvllo, (unsigned long )ret_cmsPlugin_esmdj, (float *)&ret_cmsGetPostScriptColorResource_eqlra);
    if (ret_cmsStageAllocCLutFloat_zekwi == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cmsBool ret_cmsPlugin_aizyx = cmsPlugin(NULL);
    if (ret_cmsPlugin_aizyx < 0){
    	return 0;
    }
    cmsFloat64Number ret_cmsDetectRGBProfileGamma_mbsbe = cmsDetectRGBProfileGamma(hProfile, (double )ret_cmsPlugin_aizyx);
    if (ret_cmsDetectRGBProfileGamma_mbsbe < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount > 0) {
        cmsUInt32Number index = Data[0] % tagCount;
        cmsTagSignature tagSig = cmsGetTagSignature(hProfile, index);
        if (tagSig != 0) {
            void *tagData = cmsReadTag(hProfile, tagSig);
            // Use tagData if needed; here we just ensure it's accessed
            (void)tagData;
        }
    }

    cmsCloseProfile(hProfile);
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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
