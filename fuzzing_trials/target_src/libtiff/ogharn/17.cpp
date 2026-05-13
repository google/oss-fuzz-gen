#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_17(char *fuzzData, size_t size)
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


   uint16_t TIFFComputeTilevar4;
	memset(&TIFFComputeTilevar4, 0, sizeof(TIFFComputeTilevar4));

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
   int TIFFCreateEXIFDirectoryval1 = TIFFCreateEXIFDirectory(TIFFOpenExtval1);
	if((int)TIFFCreateEXIFDirectoryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   uint32_t TIFFComputeTileval1 = TIFFComputeTile(TIFFOpenExtval1, TIFFPRINT_CURVES, TIFF_VARIABLE2, TIFFCreateEXIFDirectoryval1, TIFFComputeTilevar4);
	if((int)TIFFComputeTileval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
