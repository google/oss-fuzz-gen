#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_52(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsCreateTransformTHRvar3;
	memset(&cmsCreateTransformTHRvar3, 0, sizeof(cmsCreateTransformTHRvar3));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_KCMY_16_SE, cmsCreateTransformTHRvar3, sizeof(cmsCreateTransformTHRvar3), TYPE_GRAY_DBL, TYPE_RGB_8);
   cmsHANDLE cmsIT8LoadFromMemval1 = cmsIT8LoadFromMem(cmsCreateTransformTHRvar0, (void*)fuzzData, 64);
   return 0;
}
