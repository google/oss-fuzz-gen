#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_36(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/46oag");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   int compress2var4 = 1;
   uLongf compress2varuLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/fwfbe");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compressvar0, &compress2varuLongfsize, compressvar0, sizeof(compressvar0), compress2var4);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int uncompressval1 = uncompress(uncompressvar0, &uncompressvaruLongfsize, compressvar0, sizeof(compressvar0));
	if((int)uncompressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong adler32val1 = adler32(uncompressvaruLongfsize, zErrorval1, sizeof(zErrorval1));
	if((int)adler32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
