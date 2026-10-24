#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_17(char *fuzzData, size_t size)
{
	

   int ares_parse_ptr_replyvar4 = 1;
   struct hostent* ares_parse_ptr_replyvar5;
	memset(&ares_parse_ptr_replyvar5, 0, sizeof(ares_parse_ptr_replyvar5));

   struct hostent* ares_parse_a_replyvar2;
	memset(&ares_parse_a_replyvar2, 0, sizeof(ares_parse_a_replyvar2));

   long ares_expand_namevarLONGsize = 256;
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
   int ares_parse_a_replyval1 = ares_parse_a_reply(fuzzData, size, &ares_parse_a_replyvar2, NULL, &ares_inet_ptonval1);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int ares_expand_nameval1 = ares_expand_name(fuzzData, fuzzData, ares_parse_a_replyval1, &fuzzData, &ares_expand_namevarLONGsize);
	if(ares_expand_nameval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
