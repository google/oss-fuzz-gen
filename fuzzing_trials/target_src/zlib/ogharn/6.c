#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_6(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/qwzug");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   char* zErrorval1 = zError(0);
	if(!zErrorval1){
		fprintf(stderr, "err");
		exit(0);	}
   int compressval1 = compress(compressvar0, &compressvaruLongfsize, fuzzData, size);
	if((int)compressval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   gzFile gzdopenval1 = gzdopen(compressval1, compressvar0);
   int gzcloseval1 = gzclose(gzdopenval1);
	if((int)gzcloseval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
