#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_41(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/qg62i");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/9qg33");
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
   uLong crc32_combine_gen64val1 = crc32_combine_gen64(adler32val1);
	if((int)crc32_combine_gen64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
