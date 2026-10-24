#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
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


   tmsize_t TIFFReadFromUserBuffervar3;
	memset(&TIFFReadFromUserBuffervar3, 0, sizeof(TIFFReadFromUserBuffervar3));

   tmsize_t TIFFReadFromUserBuffervar5;
	memset(&TIFFReadFromUserBuffervar5, 0, sizeof(TIFFReadFromUserBuffervar5));

   void* TIFFReadScanlinevar1[256];
	sprintf((char *)TIFFReadScanlinevar1, "/tmp/jiqw6");
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
   int TIFFReadFromUserBufferval1 = TIFFReadFromUserBuffer(TIFFOpenExtval1, D50_Y0, NULL, TIFFReadFromUserBuffervar3, NULL, TIFFReadFromUserBuffervar5);
	if((int)TIFFReadFromUserBufferval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int TIFFReadScanlineval1 = TIFFReadScanline(TIFFOpenExtval1, TIFFReadScanlinevar1, U_NEU, TIFFReadScanlinevar3);
	if((int)TIFFReadScanlineval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
