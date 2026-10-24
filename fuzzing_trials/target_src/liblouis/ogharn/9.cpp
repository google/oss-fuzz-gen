#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <liblouis.h>

extern "C" int LLVMFuzzerTestOneInput_9(char *fuzzData, size_t size)
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


   const char* lou_versionval1 = lou_version();
	if(!lou_versionval1){
		fprintf(stderr, "err");
		exit(0);	}
   int lou_compileStringval1 = lou_compileString(fuzzData, (char *)lou_versionval1);
   return 0;
}
