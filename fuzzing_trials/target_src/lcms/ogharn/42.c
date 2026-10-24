#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_42(char *fuzzData, size_t size)
{
	

   cmsHPROFILE cmsCreateTransformvar2;
	memset(&cmsCreateTransformvar2, 0, sizeof(cmsCreateTransformvar2));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGB_HALF_FLT, cmsCreateTransformvar2, TYPE_CMYK10_16, TYPE_ABGR_HALF_FLT, TYPE_CMY_8_PLANAR);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_16_SE, cmsOpenProfileFromMemval1, TYPE_BGR_8, cmsOpenProfileFromMemval1, cmsSPOT_PRINTER_DEFAULT, TYPE_CMYK10_8, PT_YUV);
   return 0;
}
