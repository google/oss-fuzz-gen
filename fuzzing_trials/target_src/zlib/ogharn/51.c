#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_51(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/nd2cc");
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
   int gzflushval1 = gzflush(gzdopenval1, 1);
	if((int)gzflushval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int gzsetparamsval1 = gzsetparams(gzdopenval1, compressval1, compressval1);
	if((int)gzsetparamsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
