#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_16(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   long ares_expand_stringvar4 = 1;
   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, 0, ares_create_queryvar3, 0, &ares_versionval1, &ares_create_queryvarINTsize, 1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_parse_a_replyval1 = ares_parse_a_reply(ares_versionval1, 64, NULL, NULL, NULL);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_stringval1 = ares_expand_string(ares_versionval1, ares_versionval1, ares_parse_a_replyval1, NULL, &ares_expand_stringvar4);
	if(ares_expand_stringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
