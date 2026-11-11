#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_12(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/fg5hi");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   uLong crc32_combine64var0;
	memset(&crc32_combine64var0, 0, sizeof(crc32_combine64var0));

   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong crc32_combine64val1 = crc32_combine64(crc32_combine64var0, compressvaruLongfsize, compressvaruLongfsize);
	if((int)crc32_combine64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong adler32_combine64val1 = adler32_combine64(crc32_combine64val1, crc32_combine64val1, compressvaruLongfsize);
	if((int)adler32_combine64val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
