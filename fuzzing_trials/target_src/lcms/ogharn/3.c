#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, cmsNoCountry, cmsOpenProfileFromMemval1, TYPE_BGRA_16, cmsOpenProfileFromMemval1, cmsFLAGS_FORCE_CLUT, TYPE_CMYK10_16, cmsTransparency);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_CMYK_8, cmsOpenProfileFromMemval1, TYPE_KYMC_16_SE, cmsOpenProfileFromMemval1, cmsEmbeddedProfileTrue, cmsSigStatusT, cmsILLUMINANT_TYPE_UNKNOWN);
   return 0;
}
