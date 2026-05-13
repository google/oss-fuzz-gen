#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hfile.h>
#include <hts.h>
#include <sam.h>

int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
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


   int hts_readlinesvarINTsize = sizeof(fuzzData);
   char** hts_readlinesval1 = hts_readlines(fuzzData, &hts_readlinesvarINTsize);
	if(!hts_readlinesval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
