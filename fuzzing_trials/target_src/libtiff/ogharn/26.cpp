#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_26(char *fuzzData, size_t size)
{
   
    char filename[256];
    sprintf(filename, "/tmp/libfuzzer.%d", getpid());

    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    fwrite(fuzzData, size, 1, fp);
    fclose(fp);
    fuzzData = filename;


   uint16_t TIFFSwabArrayOfShortvar0;
	memset(&TIFFSwabArrayOfShortvar0, 0, sizeof(TIFFSwabArrayOfShortvar0));

   const char* TIFFGetVersionval1 = TIFFGetVersion();
	if(!TIFFGetVersionval1){
		fprintf(stderr, "err");
		exit(0);	}
   TIFFOpenOptions* TIFFOpenOptionsAllocval1 = TIFFOpenOptionsAlloc();
	if(!TIFFOpenOptionsAllocval1){
		fprintf(stderr, "err");
		exit(0);	}
   TIFF* TIFFOpenExtval1 = TIFFOpenExt(fuzzData, "r", TIFFOpenOptionsAllocval1);
	if(!TIFFOpenExtval1){
		fprintf(stderr, "err");
		exit(0);	}
   TIFFClose(TIFFOpenExtval1);
   uint64_t TIFFGetStrileOffsetval1 = TIFFGetStrileOffset(TIFFOpenExtval1, TIFF_VARIABLE2);
	if((int)TIFFGetStrileOffsetval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   TIFFSwabArrayOfShort(&TIFFSwabArrayOfShortvar0, TIFFGetStrileOffsetval1);
   return 0;
}
