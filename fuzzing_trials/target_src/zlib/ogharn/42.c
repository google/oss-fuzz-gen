#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_42(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/j95pr");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/qfqw1");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   uLong uncompress2varuLongsize = sizeof(compressvar0);
   gzFile gzwritevar0;
	memset(&gzwritevar0, 0, sizeof(gzwritevar0));

   voidpc gzwritevar1;
	memset(&gzwritevar1, 0, sizeof(gzwritevar1));

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
   int uncompress2val1 = uncompress2(uncompressvar0, &uncompressvaruLongfsize, compressvar0, &uncompress2varuLongsize);
	if((int)uncompress2val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int gzwriteval1 = gzwrite(gzwritevar0, gzwritevar1, uncompress2val1);
	if((int)gzwriteval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
