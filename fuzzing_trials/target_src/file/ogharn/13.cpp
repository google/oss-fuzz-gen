#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <magic.h>


extern "C" int LLVMFuzzerTestOneInput_13(char *fuzzData, size_t size)
{
   void** magic_load_buffersvar1[256];
	sprintf((char *)magic_load_buffersvar1, "/tmp/uhfv9");
   size_t magic_load_buffersvar2 = 1;
   size_t magic_load_buffersvar3 = 1;
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
   int magic_load_buffersval1 = magic_load_buffers(magic_openval1, (void **)magic_load_buffersvar1, &magic_load_buffersvar2, magic_load_buffersvar3);
	if((int)magic_load_buffersval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
