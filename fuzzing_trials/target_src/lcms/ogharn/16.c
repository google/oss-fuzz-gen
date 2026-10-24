#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_16(char *fuzzData, size_t size)
{
	

   cmsUInt32Number cmsCreateProofingTransformvar6;
	memset(&cmsCreateProofingTransformvar6, 0, sizeof(cmsCreateProofingTransformvar6));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_BGRA_8, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), INTENT_PRESERVE_K_PLANE_SATURATION, cmsERROR_FILE);
   cmsHTRANSFORM cmsCreateProofingTransformval1 = cmsCreateProofingTransform(cmsOpenProfileFromMemval1, TYPE_RGBA_16, cmsOpenProfileFromMemval1, TYPE_BGR_HALF_FLT, cmsOpenProfileFromMemval1, cmsTransparency, cmsCreateProofingTransformvar6, TYPE_HSV_8_PLANAR);
   return 0;
}
