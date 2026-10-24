#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <hfile.h>
#include <hts.h>
#include <sam.h>

int LLVMFuzzerTestOneInput_4(char *fuzzData, size_t size)
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


   int hts_readlistvar2 = 1;
   char** hts_readlistval1 = hts_readlist(fuzzData, BAM_FQCFAIL, &hts_readlistvar2);
	if(!hts_readlistval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
