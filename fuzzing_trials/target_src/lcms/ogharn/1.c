#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsCreateTransformTHRvar3;
	memset(&cmsCreateTransformTHRvar3, 0, sizeof(cmsCreateTransformTHRvar3));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_KCMY_16_SE, cmsCreateTransformTHRvar3, sizeof(cmsCreateTransformTHRvar3), TYPE_GRAY_DBL, TYPE_RGB_8);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_16_SE, cmsOpenProfileFromMemval1, TYPE_BGR_8, cmsERROR_RANGE, TYPE_YUV_8);
   return 0;
}
