#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_35(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, PT_MCH11, cmsOpenProfileFromMemval1, TYPE_ABGR_8_PREMUL, AVG_SURROUND, TYPE_Lab_FLT);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_KCMY_16_REV, cmsOpenProfileFromMemval1, TYPE_CMYK_8_PLANAR, cmsOpenProfileFromMemval1, INTENT_PRESERVE_K_ONLY_RELATIVE_COLORIMETRIC, TYPE_CMYK7_16, TYPE_KCMY_8);
   return 0;
}
