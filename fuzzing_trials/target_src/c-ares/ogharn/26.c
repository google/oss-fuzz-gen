#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_26(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   unsigned char* ares_expand_namevar1[256];
	sprintf(ares_expand_namevar1, "/tmp/zi8m6");
   long ares_expand_namevar4 = 1;
   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, 0, ares_create_queryvar3, 0, &ares_versionval1, &ares_create_queryvarINTsize, 1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_nameval1 = ares_expand_name(ares_versionval1, ares_expand_namevar1, strlen(ares_expand_namevar1), ares_versionval1, &ares_expand_namevar4);
	if(ares_expand_nameval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
