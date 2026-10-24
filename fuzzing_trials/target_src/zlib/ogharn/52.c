#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_52(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/tdkua");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   int compress2var4 = 1;
   uLongf compress2varuLongfsize = sizeof(compressvar0);
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
   uLong crc32val1 = crc32(compress2varuLongfsize, zErrorval1, sizeof(zErrorval1));
	if((int)crc32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
