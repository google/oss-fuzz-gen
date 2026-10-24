#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_11(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/wqz4j");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   uLongf uncompressvaruLongfsize = size;
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int uncompressval1 = uncompress(fuzzData, &uncompressvaruLongfsize, compressvar0, compressvaruLongfsize);
	if((int)uncompressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   gzFile gzdopenval1 = gzdopen(uncompressval1, zErrorval1);
   int gzdirectval1 = gzdirect(gzdopenval1);
	if((int)gzdirectval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
