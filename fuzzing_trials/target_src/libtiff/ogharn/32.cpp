#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_32(char *fuzzData, size_t size)
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


   uint32_t TIFFReadRGBAImageOrientedvar3;
	memset(&TIFFReadRGBAImageOrientedvar3, 0, sizeof(TIFFReadRGBAImageOrientedvar3));

   uint32_t TIFFDefaultStripSizevar1;
	memset(&TIFFDefaultStripSizevar1, 0, sizeof(TIFFDefaultStripSizevar1));

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
   int TIFFReadRGBAImageval1 = TIFFReadRGBAImage(TIFFOpenExtval1, UVSCALE, TIFF_VARIABLE, NULL, V_NEU);
	if((int)TIFFReadRGBAImageval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int TIFFReadRGBAImageOrientedval1 = TIFFReadRGBAImageOriented(TIFFOpenExtval1, U_NEU, D50_Y0, &TIFFReadRGBAImageOrientedvar3, TIFFPRINT_CURVES, D50_X0);
	if((int)TIFFReadRGBAImageOrientedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint32_t TIFFDefaultStripSizeval1 = TIFFDefaultStripSize(TIFFOpenExtval1, TIFFDefaultStripSizevar1);
	if((int)TIFFDefaultStripSizeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
