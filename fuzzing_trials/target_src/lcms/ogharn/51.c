#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_51(char *fuzzData, size_t size)
{
	

   cmsHPROFILE cmsCreateProofingTransformvar2;
	memset(&cmsCreateProofingTransformvar2, 0, sizeof(cmsCreateProofingTransformvar2));

   cmsHPROFILE cmsCreateProofingTransformvar4;
	memset(&cmsCreateProofingTransformvar4, 0, sizeof(cmsCreateProofingTransformvar4));

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsCreateProofingTransformTHRvar3;
	memset(&cmsCreateProofingTransformTHRvar3, 0, sizeof(cmsCreateProofingTransformTHRvar3));

   cmsUInt32Number cmsCreateProofingTransformTHRvar4;
	memset(&cmsCreateProofingTransformTHRvar4, 0, sizeof(cmsCreateProofingTransformTHRvar4));

   cmsHPROFILE cmsCreateProofingTransformTHRvar5;
	memset(&cmsCreateProofingTransformTHRvar5, 0, sizeof(cmsCreateProofingTransformTHRvar5));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_16_PLANAR, cmsCreateProofingTransformvar2, TYPE_Lab_8, cmsCreateProofingTransformvar4, sizeof(cmsCreateProofingTransformvar4), TYPE_Lab_FLT, TYPE_CMYK10_16_SE);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), cmsCreateProofingTransformTHRvar3, cmsCreateProofingTransformTHRvar4, cmsCreateProofingTransformTHRvar5, DIM_SURROUND, cmsILLUMINANT_TYPE_F8, TYPE_ALab_8);
   return 0;
}
