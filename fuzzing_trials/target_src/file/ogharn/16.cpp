#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <magic.h>


extern "C" int LLVMFuzzerTestOneInput_16(char *fuzzData, size_t size)
{
	

   magic_t magic_checkvar0;
	memset(&magic_checkvar0, 0, sizeof(magic_checkvar0));

   magic_t magic_openval1 = magic_open(MAGIC_NONE);
   //hard code path rather than default location
int magic_loadval1 = magic_load(magic_openval1, "./magic.mgc");
	if((int)magic_loadval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   const char* magic_bufferval1 = magic_buffer(magic_openval1, (void*)fuzzData, size);
	if(!magic_bufferval1){
		fprintf(stderr, "err");
		exit(0);	}
   const char* magic_fileval1 = magic_file(magic_openval1, fuzzData);
	if(!magic_fileval1){
		fprintf(stderr, "err");
		exit(0);	}
   int magic_checkval1 = magic_check(magic_checkvar0, magic_fileval1);
	if((int)magic_checkval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
