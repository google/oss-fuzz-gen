#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netcdf.h>
#include <netcdf_mem.h>

int LLVMFuzzerTestOneInput_2(char *fuzzData, size_t size)
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
	sprintf(nc_createvar0, "/tmp/sczne");
   int nc_deleteval1 = nc_delete(fuzzData);
   int nc_createval1 = nc_create(nc_createvar0, sizeof(nc_createvar0), &nc_deleteval1);
	if((int)nc_createval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   int nc__openval1 = nc__open(nc_createvar0, NC_NOFILL, NULL, &nc_deleteval1);
	if((int)nc__openval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
