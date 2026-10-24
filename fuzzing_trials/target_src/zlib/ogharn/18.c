#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_18(char *fuzzData, size_t size)
{
	

   Bytef* compress2var0[256];
	sprintf(compress2var0, "/tmp/p5baj");
   int compress2var4 = 1;
   uLongf compress2varuLongfsize = sizeof(compress2var0);
   char* zlibVersionval1 = zlibVersion();
	if(!zlibVersionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compress2var0, &compress2varuLongfsize, fuzzData, size, compress2var4);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong crc32val1 = crc32(compress2varuLongfsize, fuzzData, size);
	if((int)crc32val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
