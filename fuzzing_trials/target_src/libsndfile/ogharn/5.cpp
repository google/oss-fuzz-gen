#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sndfile.h>

extern "C" int LLVMFuzzerTestOneInput_5(char *fuzzData, size_t size)
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


   SF_INFO sf_openoverload1var2;
	memset(&sf_openoverload1var2, 0, sizeof(sf_openoverload1var2));

   sf_count_t sf_seekoverload1var1;
	memset(&sf_seekoverload1var1, 0, sizeof(sf_seekoverload1var1));

   SNDFILE* sf_openoverload1val1 = sf_open(fuzzData, SF_STR_LAST, &sf_openoverload1var2);
	if(!sf_openoverload1val1){
		fprintf(stderr, "err");
		exit(0);	}
   sf_count_t sf_seekoverload1val1 = sf_seek(sf_openoverload1val1, sf_seekoverload1var1, SF_STR_LAST);
	if((int)sf_seekoverload1val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
