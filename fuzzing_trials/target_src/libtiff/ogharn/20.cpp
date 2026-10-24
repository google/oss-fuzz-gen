#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_20(char *fuzzData, size_t size)
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


   void* TIFFReadScanlinevar1[256];
	sprintf((char *)TIFFReadScanlinevar1, "/tmp/6md8j");
   uint16_t TIFFReadScanlinevar3;
	memset(&TIFFReadScanlinevar3, 0, sizeof(TIFFReadScanlinevar3));

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
   int TIFFReadScanlineval1 = TIFFReadScanline(TIFFOpenExtval1, TIFFReadScanlinevar1, TIFFPRINT_COLORMAP, TIFFReadScanlinevar3);
	if((int)TIFFReadScanlineval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
