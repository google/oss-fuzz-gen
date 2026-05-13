#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_19(char *fuzzData, size_t size)
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


   char H5Gcreate1var0[256];
	sprintf(H5Gcreate1var0, "yrdci");
   hid_t H5Fopenval1 = H5Fopen(fuzzData, 1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   hid_t H5Gcreate1val1 = H5Gcreate1(H5Fopenval1, H5Gcreate1var0, 1);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Gcreate1val1 < 0){
		fprintf(stderr, "err");
	}
   ssize_t H5Fget_nameval1 = H5Fget_name(H5Gcreate1val1, H5Gcreate1var0, 64);
	if(0){
		fprintf(stderr, "err");
	}
	if(!H5Fget_nameval1){
		fprintf(stderr, "err");
	}
   return 0;
}
