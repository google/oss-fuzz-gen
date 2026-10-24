#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_6(char *fuzzData, size_t size)
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


   widechar lou_dotsToCharvar1;
	memset(&lou_dotsToCharvar1, 0, sizeof(lou_dotsToCharvar1));

   widechar lou_dotsToCharvar2;
	memset(&lou_dotsToCharvar2, 0, sizeof(lou_dotsToCharvar2));

   int lou_dotsToCharval1 = lou_dotsToChar(fuzzData, &lou_dotsToCharvar1, &lou_dotsToCharvar2, italic, LOU_ENDSEGMENT);
	if((int)lou_dotsToCharval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
