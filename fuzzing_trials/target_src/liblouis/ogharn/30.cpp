#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_30(char *fuzzData, size_t size)
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


   widechar lou_backTranslatevar1;
	memset(&lou_backTranslatevar1, 0, sizeof(lou_backTranslatevar1));

   widechar lou_backTranslatevar3;
	memset(&lou_backTranslatevar3, 0, sizeof(lou_backTranslatevar3));

   int lou_backTranslatevar4 = 1;
   int lou_backTranslatevar9 = 1;
   int lou_backTranslatevarINTsize = sizeof(fuzzData);
   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_backTranslateval1 = lou_backTranslate(fuzzData, &lou_backTranslatevar1, &lou_backTranslatevarINTsize, &lou_backTranslatevar3, &lou_backTranslatevar4, NULL, fuzzData, NULL, NULL, &lou_backTranslatevar9, LOU_ENDSEGMENT);
	if((int)lou_backTranslateval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
