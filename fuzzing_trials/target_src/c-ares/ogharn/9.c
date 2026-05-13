#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_9(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   ares_channel_t* ares_init_optionsvar0;
	memset(&ares_init_optionsvar0, 0, sizeof(ares_init_optionsvar0));

   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, 0, ares_create_queryvar3, 0, &ares_versionval1, &ares_create_queryvarINTsize, 1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_init_optionsval1 = ares_init_options(&ares_init_optionsvar0, NULL, ares_create_queryval1);
	if(ares_init_optionsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   ares_destroy(ares_init_optionsvar0);
   ares_cancel(ares_init_optionsvar0);
   return 0;
}
