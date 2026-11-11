#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_17(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/f6aiw");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/5gfhr");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   Bytef* compress2var2[256];
	sprintf(compress2var2, "/tmp/tss8f");
   uLong compress2var3;
	memset(&compress2var3, 0, sizeof(compress2var3));

   uLongf compress2varuLongfsize = sizeof(uncompressvar0);
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
   int compress2val1 = compress2(uncompressvar0, &compress2varuLongfsize, compress2var2, compress2var3, uncompressval1);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong crc32val1 = crc32(compress2varuLongfsize, compressvar0, sizeof(compressvar0));
	if((int)crc32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
