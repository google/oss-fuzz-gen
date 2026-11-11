#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

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


   widechar lou_backTranslatevar1;
	memset(&lou_backTranslatevar1, 0, sizeof(lou_backTranslatevar1));

   int lou_backTranslatevar2 = 1;
   widechar lou_backTranslatevar3;
	memset(&lou_backTranslatevar3, 0, sizeof(lou_backTranslatevar3));

   int lou_backTranslatevar4 = 1;
   formtype lou_backTranslatevar5;
	memset(&lou_backTranslatevar5, 0, sizeof(lou_backTranslatevar5));

   int lou_backTranslatevar10 = 1;
   int lou_backTranslatevarINTsize = sizeof(fuzzData);
   widechar lou_translatePrehyphenatedvar1;
	memset(&lou_translatePrehyphenatedvar1, 0, sizeof(lou_translatePrehyphenatedvar1));

   widechar lou_translatePrehyphenatedvar3;
	memset(&lou_translatePrehyphenatedvar3, 0, sizeof(lou_translatePrehyphenatedvar3));

   char* lou_translatePrehyphenatedvar6[256];
	sprintf((char *) lou_translatePrehyphenatedvar6, "/tmp/ixchx");
   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_backTranslateval1 = lou_backTranslate(fuzzData, &lou_backTranslatevar1, &lou_backTranslatevar2, &lou_backTranslatevar3, &lou_backTranslatevar4, &lou_backTranslatevar5, fuzzData, &lou_backTranslatevarINTsize, NULL, NULL, lou_backTranslatevar10);
	if((int)lou_backTranslateval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_translatePrehyphenatedval1 = lou_translatePrehyphenated(lou_versionval1, &lou_translatePrehyphenatedvar1, &lou_backTranslatevar2, &lou_translatePrehyphenatedvar3, &lou_backTranslatevar4, &lou_backTranslatevar1, (char *)lou_translatePrehyphenatedvar6, &lou_backTranslatevar2, &lou_backTranslatevar4, &lou_backTranslatevar2, NULL, (char *)lou_versionval1, italic);
	if((int)lou_translatePrehyphenatedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   formtype lou_getTypeformForEmphClassval1 = lou_getTypeformForEmphClass(lou_versionval1, NULL);
   return 0;
}
