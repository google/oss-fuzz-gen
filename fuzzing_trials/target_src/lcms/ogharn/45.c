#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_45(char *fuzzData, size_t size)
{
	

   cmsHPROFILE cmsCreateTransformvar2;
	memset(&cmsCreateTransformvar2, 0, sizeof(cmsCreateTransformvar2));

   cmsUInt32Number cmsCreateProofingTransformvar7;
	memset(&cmsCreateProofingTransformvar7, 0, sizeof(cmsCreateProofingTransformvar7));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGB_HALF_FLT, cmsCreateTransformvar2, TYPE_CMYK10_16, TYPE_ABGR_HALF_FLT, TYPE_CMY_8_PLANAR);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_ALab_8, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), cmsOpenProfileFromMemval1, TYPE_CMYK11_16, TYPE_CMYK12_16_SE, cmsCreateProofingTransformvar7);
   return 0;
}
