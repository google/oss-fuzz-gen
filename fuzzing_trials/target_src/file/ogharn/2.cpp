#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <magic.h>


extern "C" int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
	

   magic_t magic_openval1 = magic_open(MAGIC_NONE);
   //hard code path rather than default location
int magic_loadval1 = magic_load(magic_openval1, "./magic.mgc");
	if((int)magic_loadval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int magic_checkval1 = magic_check(magic_openval1, fuzzData);
	if((int)magic_checkval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
