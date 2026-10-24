#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_36(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsHPROFILE cmsCreateTransformTHRvar3;
	memset(&cmsCreateTransformTHRvar3, 0, sizeof(cmsCreateTransformTHRvar3));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, TYPE_KCMY_16_SE, cmsCreateTransformTHRvar3, sizeof(cmsCreateTransformTHRvar3), TYPE_GRAY_DBL, TYPE_RGB_8);
   cmsCIEXYZ* cmsD50_XYZval1 = cmsD50_XYZ();
	if(!cmsD50_XYZval1){
		fprintf(stderr, "err");
		exit(0);	}
   cmsHPROFILE cmsCreateGrayProfileTHRval1 = cmsCreateGrayProfileTHR(cmsCreateTransformTHRvar0, cmsD50_XYZval1, NULL);
   return 0;
}
