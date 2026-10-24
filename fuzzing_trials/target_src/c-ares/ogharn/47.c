#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_47(char *fuzzData, size_t size)
{
	

   unsigned short ares_create_queryvar3 = 1;
   int ares_create_queryvarINTsize = 256;
   long ares_expand_stringvarLONGsize = 256;
   void* ares_parse_ptr_replyvar2[256];
	sprintf(ares_parse_ptr_replyvar2, "/tmp/duepb");
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
   int ares_parse_ptr_replyval1 = ares_parse_ptr_reply(fuzzData, ares_expand_stringval1, ares_parse_ptr_replyvar2, ares_create_queryvarINTsize, 0, NULL);
	if(ares_parse_ptr_replyval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
