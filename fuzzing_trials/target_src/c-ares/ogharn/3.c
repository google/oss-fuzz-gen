#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   long ares_expand_stringvarLONGsize = 256;
   struct ares_addrttl ares_parse_a_replyvar3;
	memset(&ares_parse_a_replyvar3, 0, sizeof(ares_parse_a_replyvar3));

   char* ares_inet_ntopvar2[256];
	sprintf(ares_inet_ntopvar2, "/tmp/ockhb");
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
   int ares_parse_a_replyval1 = ares_parse_a_reply(fuzzData, ares_create_queryval1, NULL, &ares_parse_a_replyvar3, &ares_expand_stringval1);
	if(ares_parse_a_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char* ares_inet_ntopval1 = ares_inet_ntop(ares_parse_a_replyval1, (void*)fuzzData, ares_inet_ntopvar2, -1);
	if(!ares_inet_ntopval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
