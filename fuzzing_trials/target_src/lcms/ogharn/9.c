#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_9(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsCreateTransformTHRvar3;
	memset(&cmsCreateTransformTHRvar3, 0, sizeof(cmsCreateTransformTHRvar3));

   cmsUInt32Number cmsCreateTransformvar4;
	memset(&cmsCreateTransformvar4, 0, sizeof(cmsCreateTransformvar4));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_KCMY_16_SE, cmsCreateTransformTHRvar3, sizeof(cmsCreateTransformTHRvar3), TYPE_GRAY_DBL, TYPE_RGB_8);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_FLT, cmsOpenProfileFromMemval1, TYPE_BGR_8, cmsCreateTransformvar4, cmsSigStatusA);
   return 0;
}
