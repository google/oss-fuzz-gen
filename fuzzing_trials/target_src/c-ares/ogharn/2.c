#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
	

   struct hostent* ares_parse_a_replyvar2;
	memset(&ares_parse_a_replyvar2, 0, sizeof(ares_parse_a_replyvar2));

   struct ares_addrttl ares_parse_a_replyvar3;
	memset(&ares_parse_a_replyvar3, 0, sizeof(ares_parse_a_replyvar3));

   int ares_parse_a_replyvar4 = 1;
   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvar7 = 1;
   int ares_create_queryvarINTsize = 256;
   unsigned short ares_mkqueryvar3 = 1;
   int ares_mkqueryvar4 = 1;
   unsigned char** ares_mkqueryvar5[256];
	sprintf(ares_mkqueryvar5, "/tmp/xxuoz");
   int ares_mkqueryvarINTsize = 256;
   int ares_parse_a_replyval1 = ares_parse_a_reply(fuzzData, size, &ares_parse_a_replyvar2, &ares_parse_a_replyvar3, &ares_parse_a_replyvar4);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(NULL, ares_parse_a_replyval1, ares_parse_a_replyval1, ares_create_queryvar3, ares_parse_a_replyval1, &fuzzData, &ares_create_queryvarINTsize, ares_create_queryvar7);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_mkqueryval1 = ares_mkquery(fuzzData, 0, ares_create_queryvarINTsize, ares_mkqueryvar3, ares_mkqueryvar4, ares_mkqueryvar5, &ares_mkqueryvarINTsize);
	if(ares_mkqueryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
