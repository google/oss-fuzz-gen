#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_14(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/is42x");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   uLong compress2var3;
	memset(&compress2var3, 0, sizeof(compress2var3));

   uLongf compress2varuLongfsize = sizeof(compressvar0);
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compressvar0, &compress2varuLongfsize, zErrorval1, compress2var3, compressval1);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong adler32val1 = adler32(compress2varuLongfsize, zErrorval1, sizeof(zErrorval1));
	if((int)adler32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
