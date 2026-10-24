#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_28(char *fuzzData, size_t size)
{
	

   cmsUInt32Number cmsCreateProofingTransformvar5;
	memset(&cmsCreateProofingTransformvar5, 0, sizeof(cmsCreateProofingTransformvar5));

   cmsHPROFILE cmsCreateTransformvar0;
	memset(&cmsCreateTransformvar0, 0, sizeof(cmsCreateTransformvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_ABGR_HALF_FLT, cmsOpenProfileFromMemval1, TYPE_BGRA_8_PLANAR, cmsOpenProfileFromMemval1, cmsCreateProofingTransformvar5, TYPE_CMY_8_PLANAR, AVG_SURROUND);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsCreateTransformvar0, 0, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), 0, -1);
   return 0;
}
