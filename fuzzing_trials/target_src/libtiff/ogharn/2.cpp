#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
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
   int TIFFReadRGBAImageOrientedval1 = TIFFReadRGBAImageOriented(TIFFOpenExtval1, TIFFReadRGBAImageval1, TIFFPRINT_COLORMAP, (uint32_t *)&TIFFReadRGBAImageval1, TIFF_ANY, D50_X0);
	if((int)TIFFReadRGBAImageOrientedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int TIFFSetDirectoryval1 = TIFFSetDirectory(TIFFOpenExtval1, TIFFReadRGBAImageval1);
	if((int)TIFFSetDirectoryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
