#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_22(char *fuzzData, size_t size)
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
	sprintf((char *) lou_translatePrehyphenatedvar6, "/tmp/a8g7z");
   int lou_translatePrehyphenatedvar8 = 1;
   int lou_translatePrehyphenatedvar9 = 1;
   char* lou_translatePrehyphenatedvar10[256];
	sprintf((char *) lou_translatePrehyphenatedvar10, "/tmp/fhsee");
   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_translatePrehyphenatedval1 = lou_translatePrehyphenated(fuzzData, &lou_translatePrehyphenatedvar1, &lou_translatePrehyphenatedvar2, &lou_translatePrehyphenatedvar3, &lou_translatePrehyphenatedvar4, &lou_translatePrehyphenatedvar5, (char *)lou_translatePrehyphenatedvar6, NULL, &lou_translatePrehyphenatedvar8, &lou_translatePrehyphenatedvar9, (char *)lou_translatePrehyphenatedvar10, fuzzData, sizeof(fuzzData));
	if((int)lou_translatePrehyphenatedval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char** lou_findTablesval1 = lou_findTables((const char *)lou_translatePrehyphenatedvar10);
	if(!lou_findTablesval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
