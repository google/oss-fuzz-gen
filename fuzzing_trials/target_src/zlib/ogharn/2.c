#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/nna3g");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/rv22t");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   Bytef* compress2var2[256];
	sprintf(compress2var2, "/tmp/7d8mu");
   uLongf compress2varuLongfsize = sizeof(uncompressvar0);
   uLongf uncompress2varuLongfsize = sizeof(compressvar0);
   uLong uncompress2varuLongsize = sizeof(uncompressvar0);
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
   int compress2val1 = compress2(uncompressvar0, &compress2varuLongfsize, compress2var2, sizeof(compress2var2), 1);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int uncompress2val1 = uncompress2(compressvar0, &uncompress2varuLongfsize, uncompressvar0, &uncompress2varuLongsize);
	if((int)uncompress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
