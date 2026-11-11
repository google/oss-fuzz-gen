#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <lcms2.h>

int LLVMFuzzerTestOneInput_12(char *fuzzData, size_t size)
{
	

   cmsContext cmsCreateProofingTransformTHRvar0;
	memset(&cmsCreateProofingTransformTHRvar0, 0, sizeof(cmsCreateProofingTransformTHRvar0));

   char* cmsAllocNamedColorListvar3[256];
	sprintf(cmsAllocNamedColorListvar3, "/tmp/skvla");
   char* cmsAllocNamedColorListvar4[256];
	sprintf(cmsAllocNamedColorListvar4, "/tmp/nuimt");
   cmsHPROFILE cmsOpenProfileFromMemval1 = cmsOpenProfileFromMem((void*)fuzzData, size);
   cmsHTRANSFORM cmsCreateProofingTransformTHRval1 = cmsCreateProofingTransformTHR(cmsCreateProofingTransformTHRvar0, cmsOpenProfileFromMemval1, cmsNoCountry, cmsOpenProfileFromMemval1, TYPE_BGRA_16, cmsOpenProfileFromMemval1, cmsFLAGS_FORCE_CLUT, TYPE_CMYK10_16, cmsTransparency);
   cmsNAMEDCOLORLIST* cmsAllocNamedColorListval1 = cmsAllocNamedColorList(cmsCreateProofingTransformTHRvar0, PT_MCH11, cmsSPOT_UNKNOWN, cmsAllocNamedColorListvar3, cmsAllocNamedColorListvar4);
	if(!cmsAllocNamedColorListval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
