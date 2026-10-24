#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sndfile.h>

extern "C" int LLVMFuzzerTestOneInput_3(char *fuzzData, size_t size)
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

   SNDFILE* sf_openoverload1val1 = sf_open(fuzzData, SF_STR_LAST, &sf_openoverload1var2);
	if(!sf_openoverload1val1){
		fprintf(stderr, "err");
		exit(0);	}
   int sf_format_checkval1 = sf_format_check(&sf_openoverload1var2);
   return 0;
}
