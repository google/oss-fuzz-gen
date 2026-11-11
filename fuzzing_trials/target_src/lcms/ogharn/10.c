#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_CMYKA_8, cmsOpenProfileFromMemval1, cmsSigStatusT, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), TYPE_CMYK10_16, TYPE_ABGR_8_PLANAR);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_BGR_16_PLANAR, cmsOpenProfileFromMemval1, TYPE_BGR_8, cmsSPOT_DIAMOND, TYPE_GRAY_8_REV);
   return 0;
}
