#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_38(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/opudg");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/wynqh");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   Bytef* compress2var2[256];
	sprintf(compress2var2, "/tmp/vp8a8");
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
   return 0;
}
