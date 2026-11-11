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

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        return 0;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromFile to cmsDetectRGBProfileGamma
    cmsBool ret_cmsPlugin_aizyx = cmsPlugin(NULL);
    if (ret_cmsPlugin_aizyx < 0){
    	return 0;
    }
    cmsFloat64Number ret_cmsDetectRGBProfileGamma_mbsbe = cmsDetectRGBProfileGamma(hProfile, (double )ret_cmsPlugin_aizyx);
    if (ret_cmsDetectRGBProfileGamma_mbsbe < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsDetectRGBProfileGamma to cmsGetPostScriptColorResource
    cmsContext ret_cmsGetProfileContextID_zeblx = cmsGetProfileContextID(0);
    cmsHPROFILE ret_cmsCreateLab2Profile_fxgxr = cmsCreateLab2Profile(NULL);
    cmsFloat64Number ret_cmsSetAdaptationState_wvqwl = cmsSetAdaptationState(INTENT_ABSOLUTE_COLORIMETRIC);
    if (ret_cmsSetAdaptationState_wvqwl < 0){
    	return 0;
    }
    cmsIOHANDLER* ret_cmsOpenIOhandlerFromNULL_ckkwq = cmsOpenIOhandlerFromNULL(0);
    if (ret_cmsOpenIOhandlerFromNULL_ckkwq == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cmsOpenIOhandlerFromNULL_ckkwq) {
    	return 0;
    }
    cmsUInt32Number ret_cmsGetPostScriptColorResource_selsr = cmsGetPostScriptColorResource(ret_cmsGetProfileContextID_zeblx, 0, ret_cmsCreateLab2Profile_fxgxr, (unsigned long )ret_cmsDetectRGBProfileGamma_mbsbe, (unsigned long )ret_cmsSetAdaptationState_wvqwl, ret_cmsOpenIOhandlerFromNULL_ckkwq);
    if (ret_cmsGetPostScriptColorResource_selsr < 0){
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

            // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsReadTag to cmsCreateContext
            char bdhupqre[1024] = "jilrk";
            cmsBool ret_cmsPlugin_lbguq = cmsPlugin(bdhupqre);
            if (ret_cmsPlugin_lbguq < 0){
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!bdhupqre) {
            	return 0;
            }
            // Ensure dataflow is valid (i.e., non-null)
            if (!tagData) {
            	return 0;
            }
            cmsContext ret_cmsCreateContext_ckzxa = cmsCreateContext(bdhupqre, tagData);
            // End mutation: Producer.APPEND_MUTATOR
            
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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
