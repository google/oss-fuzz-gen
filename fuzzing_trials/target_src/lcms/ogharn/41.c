#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_41(char *fuzzData, size_t size)
{
	

   cmsUInt32Number cmsCreateProofingTransformvar5;
	memset(&cmsCreateProofingTransformvar5, 0, sizeof(cmsCreateProofingTransformvar5));

   cmsUInt32Number cmsCreateTransformvar4;
	memset(&cmsCreateTransformvar4, 0, sizeof(cmsCreateTransformvar4));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_ABGR_HALF_FLT, cmsOpenProfileFromMemval1, TYPE_BGRA_8_PLANAR, cmsOpenProfileFromMemval1, cmsCreateProofingTransformvar5, TYPE_CMY_8_PLANAR, AVG_SURROUND);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGB_16, cmsOpenProfileFromMemval1, cmsV2Unicode, cmsCreateTransformvar4, cmsFLAGS_CLUT_PRE_LINEARIZATION);
   return 0;
}
