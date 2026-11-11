#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_10(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/cl03x");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/x81nh");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   uLong compress2var3;
	memset(&compress2var3, 0, sizeof(compress2var3));

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
   int compress2val1 = compress2(uncompressvar0, &adler32val1, NULL, compress2var3, 0);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
