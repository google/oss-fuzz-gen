#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_14(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformval1 = cmsCreateTransform(cmsOpenProfileFromMemval1, TYPE_BGRA_8, cmsOpenProfileFromMemval1, sizeof(cmsOpenProfileFromMemval1), INTENT_PRESERVE_K_PLANE_SATURATION, cmsERROR_FILE);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_ABGR_8_PREMUL, cmsOpenProfileFromMemval1, PT_MCH15, cmsOpenProfileFromMemval1, INTENT_PRESERVE_K_ONLY_RELATIVE_COLORIMETRIC, cmsILLUMINANT_TYPE_F2, TYPE_YUV_8_PLANAR);
   return 0;
}
