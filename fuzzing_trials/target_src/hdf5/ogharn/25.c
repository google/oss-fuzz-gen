#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_25(char *fuzzData, size_t size)
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


   haddr_t H5Fget_eoavar0;
	memset(&H5Fget_eoavar0, 0, (sizeof H5Fget_eoavar0));

   hid_t H5Fopenval1 = H5Fopen(fuzzData, 1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   hid_t H5Freopenval1 = H5Freopen(H5Fopenval1);
	if(H5Freopenval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Fget_eoaval1 = H5Fget_eoa(H5Freopenval1, &H5Fget_eoavar0);
	if(H5Fget_eoaval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
