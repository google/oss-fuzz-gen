#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_58(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsCreateProofingTransformTHRvar5;
	memset(&cmsCreateProofingTransformTHRvar5, 0, sizeof(cmsCreateProofingTransformTHRvar5));

   cmsUInt32Number cmsCreateProofingTransformvar5;
	memset(&cmsCreateProofingTransformvar5, 0, sizeof(cmsCreateProofingTransformvar5));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_CMYKA_8, cmsOpenProfileFromMemval1, TYPE_KYMC_16, cmsCreateProofingTransformTHRvar5, sizeof(cmsCreateProofingTransformTHRvar5), TYPE_CMYK9_16_SE, cmsTransparency);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_BGR_16, cmsOpenProfileFromMemval1, TYPE_BGRA_8_PLANAR, cmsOpenProfileFromMemval1, cmsCreateProofingTransformvar5, PT_MCH2, PT_HLS);
   return 0;
}
