#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_28(char *fuzzData, size_t size)
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


   tdir_t TIFFSetDirectoryvar1;
	memset(&TIFFSetDirectoryvar1, 0, sizeof(TIFFSetDirectoryvar1));

   uint32_t TIFFRawStripSizevar1;
	memset(&TIFFRawStripSizevar1, 0, sizeof(TIFFRawStripSizevar1));

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
   int TIFFSetDirectoryval1 = TIFFSetDirectory(TIFFOpenExtval1, TIFFSetDirectoryvar1);
	if((int)TIFFSetDirectoryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   tmsize_t TIFFRawStripSizeval1 = TIFFRawStripSize(TIFFOpenExtval1, TIFFRawStripSizevar1);
	if((int)TIFFRawStripSizeval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
