#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_51(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   long ares_expand_stringvarLONGsize = 256;
   ares_channel_t* ares_init_optionsvar0;
	memset(&ares_init_optionsvar0, 0, sizeof(ares_init_optionsvar0));

   struct ares_options ares_init_optionsvar1;
	memset(&ares_init_optionsvar1, 0, sizeof(ares_init_optionsvar1));

   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, 0, ares_create_queryvar3, 0, &ares_versionval1, &ares_create_queryvarINTsize, 1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_stringval1 = ares_expand_string(fuzzData, fuzzData, size, ares_versionval1, &ares_expand_stringvarLONGsize);
	if(ares_expand_stringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_init_optionsval1 = ares_init_options(&ares_init_optionsvar0, &ares_init_optionsvar1, ares_expand_stringval1);
	if(ares_init_optionsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_dupval1 = ares_dup(ares_init_optionsvar0, ares_init_optionsvar0);
	if(ares_dupval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
