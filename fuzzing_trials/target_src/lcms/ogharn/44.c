#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_44(char *fuzzData, size_t size)
{
	

   cmsHPROFILE cmsCreateTransformvar2;
	memset(&cmsCreateTransformvar2, 0, sizeof(cmsCreateTransformvar2));

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGB_HALF_FLT, cmsCreateTransformvar2, TYPE_CMYK10_16, TYPE_ABGR_HALF_FLT, TYPE_CMY_8_PLANAR);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, PT_MCH15, cmsOpenProfileFromMemval1, TYPE_RGB_DBL, cmsCreateTransformvar2, cmsSPOT_UNKNOWN, cmsGlossy, TYPE_ABGR_16);
   return 0;
}
