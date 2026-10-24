#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_18(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsUInt32Number cmsCreateTransformTHRvar6;
	memset(&cmsCreateTransformTHRvar6, 0, sizeof(cmsCreateTransformTHRvar6));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_BGRA_8, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), INTENT_PRESERVE_K_PLANE_SATURATION, cmsERROR_FILE);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_RGBA_16_PLANAR, cmsOpenProfileFromMemval1, TYPE_BGR_16_PLANAR, INTENT_PRESERVE_K_PLANE_RELATIVE_COLORIMETRIC, cmsCreateTransformTHRvar6);
   return 0;
}
