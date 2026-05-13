#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_39(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/x6hw5");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/2ihm4");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
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
   int gzwriteval1 = gzwrite(gzwritevar0, gzwritevar1, uncompressval1);
	if((int)gzwriteval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int gzeofval1 = gzeof(gzwritevar0);
	if((int)gzeofval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
