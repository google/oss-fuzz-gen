#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_46(char *fuzzData, size_t size)
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


   char* lou_getTypeformForEmphClassvar1[256];
	sprintf((char *)lou_getTypeformForEmphClassvar1, "/tmp/0juqv");
   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   formtype lou_getTypeformForEmphClassval1 = lou_getTypeformForEmphClass(fuzzData, (char *)lou_getTypeformForEmphClassvar1);
   return 0;
}
