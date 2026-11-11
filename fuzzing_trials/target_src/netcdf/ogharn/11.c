#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netcdf.h>
#include <netcdf_mem.h>

int LLVMFuzzerTestOneInput_11(char *fuzzData, size_t size)
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


   int nc__open_mpvar1 = 1;
   size_t nc__open_mpvar3 = 1;
   int nc__open_mpval1 = nc__open_mp(fuzzData, nc__open_mpvar1, NC_FILL_UBYTE, &nc__open_mpvar3, NULL);
	if((int)nc__open_mpval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
