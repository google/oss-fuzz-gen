#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <zlib.h>

int LLVMFuzzerTestOneInput_49(char *fuzzData, size_t size)
{
	

   Bytef* compressvar0[256];
	sprintf(compressvar0, "/tmp/gxzkk");
   uLongf compressvaruLongfsize = sizeof(compressvar0);
   Bytef* uncompressvar0[256];
	sprintf(uncompressvar0, "/tmp/r5bht");
   uLongf uncompressvaruLongfsize = sizeof(uncompressvar0);
   z_streamp deflateBoundvar0;
	memset(&deflateBoundvar0, 0, sizeof(deflateBoundvar0));

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
   uLong crc32_combine_opval1 = crc32_combine_op(uncompressvaruLongfsize, compressvaruLongfsize, uncompressvaruLongfsize);
	if((int)crc32_combine_opval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uLong deflateBoundval1 = deflateBound(deflateBoundvar0, crc32_combine_opval1);
	if((int)deflateBoundval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
