#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netcdf.h>
#include <netcdf_mem.h>

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


   size_t nc_create_memvar2 = 1;
   int nc_deleteval1 = nc_delete(fuzzData);
   int nc_create_memval1 = nc_create_mem(fuzzData, NC_FIRSTUSERTYPEID, nc_create_memvar2, &nc_deleteval1);
	if((int)nc_create_memval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
