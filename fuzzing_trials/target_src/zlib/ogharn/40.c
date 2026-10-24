#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_40(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/dvle3");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/ohn9w");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int uncompressval1 = uncompress(uncompressvar0, &uncompressvaruLongfsize, compressvar0, compressvaruLongfsize);
	if((int)uncompressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong adler32val1 = adler32(uncompressvaruLongfsize, uncompressvar0, sizeof(uncompressvar0));
	if((int)adler32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compressvar0, &adler32val1, uncompressvar0, compressvaruLongfsize, 0);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
