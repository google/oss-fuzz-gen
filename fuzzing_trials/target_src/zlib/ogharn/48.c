#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_48(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/67zy6");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/xpuz6");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   gzFile gzwritevar0;
	memset(&gzwritevar0, 0, sizeof(gzwritevar0));

   voidpc gzwritevar1;
	memset(&gzwritevar1, 0, sizeof(gzwritevar1));

   Bytef* compress2var2[256];
	sprintf(compress2var2, "/tmp/8bya9");
   uLongf compress2varuLongfsize = sizeof(compressvar0);
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
   int gzwriteval1 = gzwrite(gzwritevar0, gzwritevar1, uncompressval1);
	if((int)gzwriteval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int compress2val1 = compress2(compressvar0, &compress2varuLongfsize, compress2var2, uncompressvaruLongfsize, gzwriteval1);
	if((int)compress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
