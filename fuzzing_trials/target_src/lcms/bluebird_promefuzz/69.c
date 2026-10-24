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

int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    write_dummy_file(Data, Size);

    cmsHPROFILE hProfile = cmsOpenProfileFromFile("./dummy_file", "r");
    if (!hProfile) {
        return 0;
    }

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


    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cmsGetTagCount to cmsSliceSpace16
    cmsUInt32Number ret_cmsGetHeaderRenderingIntent_erhqt = cmsGetHeaderRenderingIntent(hProfile);
    if (ret_cmsGetHeaderRenderingIntent_erhqt < 0){
    	return 0;
    }
    cmsNAMEDCOLORLIST* ret_cmsDupNamedColorList_igtnc = cmsDupNamedColorList(NULL);
    if (ret_cmsDupNamedColorList_igtnc == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_cmsDupNamedColorList_igtnc) {
    	return 0;
    }
    cmsBool ret_cmsSliceSpace16_zcsoh = cmsSliceSpace16((unsigned long )tagCount, &ret_cmsGetHeaderRenderingIntent_erhqt, 0, (void *)ret_cmsDupNamedColorList_igtnc);
    if (ret_cmsSliceSpace16_zcsoh < 0){
    	return 0;
    }
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

    LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
