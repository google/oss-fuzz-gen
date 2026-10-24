#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hfile.h>
#include <hts.h>
#include <sam.h>

int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
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


   char* hts_versionval1 = hts_version();
	if(!hts_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   htsFile* hts_openval1 = hts_open(fuzzData, "r");
	if(!hts_openval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
