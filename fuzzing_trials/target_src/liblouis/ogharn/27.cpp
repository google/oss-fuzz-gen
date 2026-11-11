#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_27(char *fuzzData, size_t size)
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


   widechar lou_translatePrehyphenatedvar1;
	memset(&lou_translatePrehyphenatedvar1, 0, sizeof(lou_translatePrehyphenatedvar1));

   int lou_translatePrehyphenatedvar2 = 1;
   widechar lou_translatePrehyphenatedvar3;
	memset(&lou_translatePrehyphenatedvar3, 0, sizeof(lou_translatePrehyphenatedvar3));

   int lou_translatePrehyphenatedvar4 = 1;
   formtype lou_translatePrehyphenatedvar5;
	memset(&lou_translatePrehyphenatedvar5, 0, sizeof(lou_translatePrehyphenatedvar5));

   char* lou_translatePrehyphenatedvar6[256];
	sprintf((char *) lou_translatePrehyphenatedvar6, "/tmp/4t3tb");
   int lou_translatePrehyphenatedvar8 = 1;
   int lou_translatePrehyphenatedvar9 = 1;
   char* lou_translatePrehyphenatedvar10[256];
	sprintf((char *) lou_translatePrehyphenatedvar10, "/tmp/pbupi");
   widechar lou_translatevar1;
	memset(&lou_translatevar1, 0, sizeof(lou_translatevar1));

   int lou_translatevar2 = 1;
   int lou_translatevarINTsize = sizeof(NULL);
   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_translatePrehyphenatedval1 = lou_translatePrehyphenated(fuzzData, &lou_translatePrehyphenatedvar1, &lou_translatePrehyphenatedvar2, &lou_translatePrehyphenatedvar3, &lou_translatePrehyphenatedvar4, &lou_translatePrehyphenatedvar5, (char *)lou_translatePrehyphenatedvar6, NULL, &lou_translatePrehyphenatedvar8, &lou_translatePrehyphenatedvar9, (char *)lou_translatePrehyphenatedvar10, fuzzData, sizeof(fuzzData));
	if((int)lou_translatePrehyphenatedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_translateval1 = lou_translate(fuzzData, &lou_translatevar1, &lou_translatevar2, &lou_translatePrehyphenatedvar1, &lou_translatePrehyphenatedvar8, &lou_translatePrehyphenatedvar3, NULL, &lou_translatevarINTsize, &lou_translatePrehyphenatedvar2, &lou_translatePrehyphenatedvar4, LOU_ENDSEGMENT);
	if((int)lou_translateval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_translateStringval1 = lou_translateString(fuzzData, &lou_translatePrehyphenatedvar5, &lou_translatePrehyphenatedvar2, &lou_translatePrehyphenatedvar3, &lou_translatePrehyphenatedvar8, &lou_translatePrehyphenatedvar5, fuzzData, lou_translatevarINTsize);
	if((int)lou_translateStringval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_compileStringval1 = lou_compileString(fuzzData, (const char *)lou_translatePrehyphenatedvar6);
   return 0;
}
