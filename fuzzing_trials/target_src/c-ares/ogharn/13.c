#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_13(char *fuzzData, size_t size)
{
	

   int ares_parse_ptr_replyvar4 = 1;
   struct hostent* ares_parse_ptr_replyvar5;
	memset(&ares_parse_ptr_replyvar5, 0, sizeof(ares_parse_ptr_replyvar5));

   int ares_parse_a_replyvar4 = 1;
   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvar4 = 1;
   int ares_mkqueryvar2 = 1;
   unsigned short ares_mkqueryvar3 = 1;
   int ares_mkqueryvarINTsize = 256;
   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_parse_ptr_replyval1 = ares_parse_ptr_reply(fuzzData, size, (void*)ares_versionval1, sizeof(ares_versionval1), ares_parse_ptr_replyvar4, &ares_parse_ptr_replyvar5);
	if(ares_parse_ptr_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_parse_a_replyval1 = ares_parse_a_reply(ares_versionval1, strlen(ares_versionval1), ares_parse_ptr_replyvar5, NULL, &ares_parse_a_replyvar4);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(ares_versionval1, strlen(ares_versionval1), ares_parse_a_replyval1, ares_create_queryvar3, ares_create_queryvar4, &ares_versionval1, &ares_parse_ptr_replyval1, ares_parse_a_replyvar4);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_mkqueryval1 = ares_mkquery(fuzzData, ares_create_queryval1, ares_mkqueryvar2, ares_mkqueryvar3, 0, &fuzzData, &ares_mkqueryvarINTsize);
	if(ares_mkqueryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
