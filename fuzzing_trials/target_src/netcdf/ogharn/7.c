#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netcdf.h>
#include <netcdf_mem.h>

int LLVMFuzzerTestOneInput_7(char *fuzzData, size_t size)
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


   char* nc_createvar0[256];
	sprintf(nc_createvar0, "/tmp/ntjgm");
   int nc_deleteval1 = nc_delete(fuzzData);
   int nc_createval1 = nc_create(nc_createvar0, sizeof(nc_createvar0), &nc_deleteval1);
	if((int)nc_createval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int nc_openval1 = nc_open(nc_createvar0, sizeof(nc_createvar0), &nc_deleteval1);
	if((int)nc_openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
