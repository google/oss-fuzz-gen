#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_15(char *fuzzData, size_t size)
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


   widechar lou_charToDotsvar1;
	memset(&lou_charToDotsvar1, 0, sizeof(lou_charToDotsvar1));

   widechar lou_charToDotsvar2;
	memset(&lou_charToDotsvar2, 0, sizeof(lou_charToDotsvar2));

   int lou_charToDotsval1 = lou_charToDots(fuzzData, &lou_charToDotsvar1, &lou_charToDotsvar2, italic, LOU_ENDSEGMENT);
	if((int)lou_charToDotsval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
