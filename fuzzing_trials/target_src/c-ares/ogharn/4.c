#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_4(char *fuzzData, size_t size)
{
	

   int ares_parse_ptr_replyvar4 = 1;
   struct hostent* ares_parse_ptr_replyvar5;
	memset(&ares_parse_ptr_replyvar5, 0, sizeof(ares_parse_ptr_replyvar5));

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvar6 = 1;
   long ares_expand_namevar4 = 1;
   char* ares_versionval1 = ares_version(NULL);
	if(!ares_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_parse_ptr_replyval1 = ares_parse_ptr_reply(fuzzData, size, (void*)ares_versionval1, sizeof(ares_versionval1), ares_parse_ptr_replyvar4, &ares_parse_ptr_replyvar5);
	if(ares_parse_ptr_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_inet_ptonval1 = ares_inet_pton(ares_parse_ptr_replyval1, ares_versionval1, (void*)fuzzData);
	if(ares_inet_ptonval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_create_queryval1 = ares_create_query(ares_versionval1, strlen(ares_versionval1), ares_inet_ptonval1, ares_create_queryvar3, ares_parse_ptr_replyval1, &ares_versionval1, &ares_create_queryvar6, 0);
	if(ares_create_queryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_nameval1 = ares_expand_name(fuzzData, fuzzData, ares_create_queryval1, NULL, &ares_expand_namevar4);
	if(ares_expand_nameval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
