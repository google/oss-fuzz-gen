#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sndfile.h>

extern "C" int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
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

   char* sf_error_stroverload1var1[256];
	sprintf((char *)sf_error_stroverload1var1, "/tmp/rys45");
   sf_count_t sf_seekvar1;
	memset(&sf_seekvar1, 0, sizeof(sf_seekvar1));

   SNDFILE* sf_openoverload1val1 = sf_open(fuzzData, SF_STR_LAST, &sf_openoverload1var2);
	if(!sf_openoverload1val1){
		fprintf(stderr, "err");
		exit(0);	}
   int sf_commandoverload1val1 = sf_command(sf_openoverload1val1, SF_STR_LAST, NULL, sizeof(NULL));
	if((int)sf_commandoverload1val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int sf_error_stroverload1val1 = sf_error_str(sf_openoverload1val1, (char *)sf_error_stroverload1var1, sizeof(sf_error_stroverload1var1));
	if((int)sf_error_stroverload1val1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   sf_count_t sf_seekval1 = sf_seek(sf_openoverload1val1, sf_seekvar1, 0);
	if((int)sf_seekval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
