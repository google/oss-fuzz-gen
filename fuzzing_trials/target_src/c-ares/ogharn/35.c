#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_35(char *fuzzData, size_t size)
{
	

   struct hostent* ares_parse_a_replyvar2;
	memset(&ares_parse_a_replyvar2, 0, sizeof(ares_parse_a_replyvar2));

   struct ares_addrttl ares_parse_a_replyvar3;
	memset(&ares_parse_a_replyvar3, 0, sizeof(ares_parse_a_replyvar3));

   int ares_parse_a_replyvar4 = 1;
   unsigned short ares_create_queryvar3 = 1;
   unsigned char** ares_create_queryvar5[256];
	sprintf(ares_create_queryvar5, "/tmp/gt5hp");
   int ares_create_queryvarINTsize = 256;
   int ares_parse_a_replyval1 = ares_parse_a_reply(fuzzData, size, &ares_parse_a_replyvar2, &ares_parse_a_replyvar3, &ares_parse_a_replyvar4);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(fuzzData, 1, ares_parse_a_replyval1, ares_create_queryvar3, 1, ares_create_queryvar5, &ares_create_queryvarINTsize, -1);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
