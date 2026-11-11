#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   unsigned short ares_mkqueryvar3 = 1;
   int ares_mkqueryvar6 = 1;
   unsigned char** ares_expand_stringvar3[256];
	sprintf(ares_expand_stringvar3, "/tmp/u3l8k");
   long ares_expand_stringvar4 = 1;
   struct ares_soa_reply* ares_parse_soa_replyvar2;
	memset(&ares_parse_soa_replyvar2, 0, sizeof(ares_parse_soa_replyvar2));

   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, 0, ares_create_queryvar3, 0, &ares_versionval1, &ares_create_queryvarINTsize, 1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_mkqueryval1 = ares_mkquery(ares_versionval1, ares_create_queryval1, 64, ares_mkqueryvar3, 1, &fuzzData, &ares_mkqueryvar6);
	if(ares_mkqueryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_stringval1 = ares_expand_string(fuzzData, fuzzData, size, ares_expand_stringvar3, &ares_expand_stringvar4);
	if(ares_expand_stringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_parse_soa_replyval1 = ares_parse_soa_reply(fuzzData, ares_expand_stringval1, &ares_parse_soa_replyvar2);
	if(ares_parse_soa_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
