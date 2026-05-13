#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_8(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar2;
	memset(&cmsCreateBCHSWabstractProfileTHRvar2, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar2));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar3;
	memset(&cmsCreateBCHSWabstractProfileTHRvar3, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar3));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar4;
	memset(&cmsCreateBCHSWabstractProfileTHRvar4, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar4));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar5;
	memset(&cmsCreateBCHSWabstractProfileTHRvar5, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar5));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, cmsNoCountry, cmsOpenProfileFromMemval1, TYPE_BGRA_16, cmsOpenProfileFromMemval1, cmsFLAGS_FORCE_CLUT, TYPE_CMYK10_16, cmsTransparency);
   cmsHPROFILE cmsCreateBCHSWabstractProfileTHRval1 = cmsCreateBCHSWabstractProfileTHR(cmsCreateProofingTransformTHRvar0, 64, cmsCreateBCHSWabstractProfileTHRvar2, cmsCreateBCHSWabstractProfileTHRvar3, cmsCreateBCHSWabstractProfileTHRvar4, cmsCreateBCHSWabstractProfileTHRvar5, 0, 1);
   return 0;
}
