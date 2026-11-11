#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_64(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsCreateProofingTransformTHRvar5;
	memset(&cmsCreateProofingTransformTHRvar5, 0, sizeof(cmsCreateProofingTransformTHRvar5));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_CMYKA_8, cmsOpenProfileFromMemval1, TYPE_KYMC_16, cmsCreateProofingTransformTHRvar5, sizeof(cmsCreateProofingTransformTHRvar5), TYPE_CMYK9_16_SE, cmsTransparency);
   cmsHPROFILE cmsCreateLinearizationDeviceLinkTHRval1 = cmsCreateLinearizationDeviceLinkTHR(cmsCreateProofingTransformTHRvar0, cmsSigMCH4Data, NULL);
   return 0;
}
