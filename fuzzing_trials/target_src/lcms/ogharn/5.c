#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   void* cmsDupContextvar1[256];
	sprintf(cmsDupContextvar1, "/tmp/plz85");
   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, cmsNoCountry, cmsOpenProfileFromMemval1, TYPE_BGRA_16, cmsOpenProfileFromMemval1, cmsFLAGS_FORCE_CLUT, TYPE_CMYK10_16, cmsTransparency);
   cmsContext cmsDupContextval1 = cmsDupContext(cmsCreateProofingTransformTHRvar0, cmsDupContextvar1);
   return 0;
}
