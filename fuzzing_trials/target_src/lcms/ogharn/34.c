#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_34(char *fuzzData, size_t size)
{
	

   cmsUInt32Number cmsCreateProofingTransformvar5;
	memset(&cmsCreateProofingTransformvar5, 0, sizeof(cmsCreateProofingTransformvar5));

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_ABGR_HALF_FLT, cmsOpenProfileFromMemval1, TYPE_BGRA_8_PLANAR, cmsOpenProfileFromMemval1, cmsCreateProofingTransformvar5, TYPE_CMY_8_PLANAR, AVG_SURROUND);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_RGB_DBL, cmsOpenProfileFromMemval1, PT_MCH15, cmsSPOT_DIAMOND, cmsTransparency);
   return 0;
}
