#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_45(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/t0wsx");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* compress2var0[256];
	sprintf(compress2var0, "/tmp/66tmv");
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong crc32_zval1 = crc32_z(compressvaruLongfsize, zErrorval1, compressvaruLongfsize);
	if((int)crc32_zval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compress2var0, &crc32_zval1, compressvar0, compressvaruLongfsize, 0);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
