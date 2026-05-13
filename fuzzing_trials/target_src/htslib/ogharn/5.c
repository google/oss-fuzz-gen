#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hfile.h>
#include <hts.h>
#include <sam.h>

int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
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


   htsFormat hts_open_formatvar2;
	memset(&hts_open_formatvar2, 0, sizeof(hts_open_formatvar2));

   char* hts_versionval1 = hts_version();
	if(!hts_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   htsFile* hts_open_formatval1 = hts_open_format(fuzzData, "r", &hts_open_formatvar2);
	if(!hts_open_formatval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
