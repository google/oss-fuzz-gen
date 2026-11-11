#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_26(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar2;
	memset(&cmsCreateBCHSWabstractProfileTHRvar2, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar2));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar3;
	memset(&cmsCreateBCHSWabstractProfileTHRvar3, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar3));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar4;
	memset(&cmsCreateBCHSWabstractProfileTHRvar4, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar4));

   cmsFloat64Number cmsCreateBCHSWabstractProfileTHRvar5;
	memset(&cmsCreateBCHSWabstractProfileTHRvar5, 0, sizeof(cmsCreateBCHSWabstractProfileTHRvar5));

   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, PT_MCH11, cmsOpenProfileFromMemval1, TYPE_ABGR_8_PREMUL, AVG_SURROUND, TYPE_Lab_FLT);
   cmsHPROFILE cmsCreateBCHSWabstractProfileTHRval1 = cmsCreateBCHSWabstractProfileTHR(cmsCreateTransformTHRvar0, lcmsSignature, cmsCreateBCHSWabstractProfileTHRvar2, cmsCreateBCHSWabstractProfileTHRvar3, cmsCreateBCHSWabstractProfileTHRvar4, cmsCreateBCHSWabstractProfileTHRvar5, PT_HSV, TYPE_BGR_HALF_FLT);
   return 0;
}
