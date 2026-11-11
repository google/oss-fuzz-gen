#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_4(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateTransformTHRvar0;
	memset(&cmsCreateTransformTHRvar0, 0, sizeof(cmsCreateTransformTHRvar0));

   char* cmsCreateDeviceLinkFromCubeFileTHRvar1[256];
	sprintf(cmsCreateDeviceLinkFromCubeFileTHRvar1, "/tmp/wy21a");
   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateTransformTHRval1 = cmsCreateTransformTHR(cmsCreateTransformTHRvar0, cmsOpenProfileFromMemval1, PT_MCH11, cmsOpenProfileFromMemval1, TYPE_ABGR_8_PREMUL, AVG_SURROUND, TYPE_Lab_FLT);
   cmsHPROFILE cmsCreateDeviceLinkFromCubeFileTHRval1 = cmsCreateDeviceLinkFromCubeFileTHR(cmsCreateTransformTHRvar0, cmsCreateDeviceLinkFromCubeFileTHRvar1);
   return 0;
}
