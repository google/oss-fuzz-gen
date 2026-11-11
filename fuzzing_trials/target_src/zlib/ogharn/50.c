#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_50(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/i24v2");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   gzFile gzdopenval1 = gzdopen(compressval1, compressvar0);
   int gzdirectval1 = gzdirect(gzdopenval1);
	if((int)gzdirectval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int gzbufferval1 = gzbuffer(gzdopenval1, compressval1);
	if((int)gzbufferval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
