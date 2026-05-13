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

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        return 0;
    }


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsOpenProfileFromFile to cmsSetProfileVersion
    cmsBool ret_cmsMD5computeID_qetxp = cmsMD5computeID(hProfile);
    if (ret_cmsMD5computeID_qetxp < 0){
    	return 0;
    }
    cmsSetProfileVersion(hProfile, (double )ret_cmsMD5computeID_qetxp);
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


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsGetTagCount to cmsCreateTransform
    cmsHPROFILE ret_cmsCreate_sRGBProfile_hidmo = cmsCreate_sRGBProfile();
    cmsUInt32Number ret_cmsMLUtranslationsCount_asihl = cmsMLUtranslationsCount(NULL);
    if (ret_cmsMLUtranslationsCount_asihl < 0){
    	return 0;
    }
    cmsHPROFILE ret_cmsCreate_sRGBProfile_avmek = cmsCreate_sRGBProfile();
    cmsFloat64Number ret_cmsSetAdaptationState_whwrr = cmsSetAdaptationState(cmsERROR_READ);
    if (ret_cmsSetAdaptationState_whwrr < 0){
    	return 0;
    }
    cmsFloat64Number ret_cmsSetAdaptationState_nnlyo = cmsSetAdaptationState(PT_HSV);
    if (ret_cmsSetAdaptationState_nnlyo < 0){
    	return 0;
    }
    cmsHTRANSFORM ret_cmsCreateTransform_zhbeq = cmsCreateTransform(ret_cmsCreate_sRGBProfile_hidmo, ret_cmsMLUtranslationsCount_asihl, ret_cmsCreate_sRGBProfile_avmek, (unsigned long )tagCount, (unsigned long )ret_cmsSetAdaptationState_whwrr, (unsigned long )ret_cmsSetAdaptationState_nnlyo);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
