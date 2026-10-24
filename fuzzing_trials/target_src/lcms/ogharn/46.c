#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_46(char *fuzzData, size_t size)
{
	

   cmsHPROFILE cmsCreateProofingTransformvar2;
	memset(&cmsCreateProofingTransformvar2, 0, sizeof(cmsCreateProofingTransformvar2));

   cmsHPROFILE cmsCreateProofingTransformvar4;
	memset(&cmsCreateProofingTransformvar4, 0, sizeof(cmsCreateProofingTransformvar4));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_16_PLANAR, cmsCreateProofingTransformvar2, TYPE_Lab_8, cmsCreateProofingTransformvar4, sizeof(cmsCreateProofingTransformvar4), TYPE_Lab_FLT, TYPE_CMYK10_16_SE);
   cmsBool cmsCloseProfileval1 = cmsCloseProfile(cmsCreateProofingTransformvar2);
	if((int)cmsCloseProfileval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
