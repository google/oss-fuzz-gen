#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_1(char *fuzzData, size_t size)
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
	sprintf(H5Gcreate1var0, "yhoom");
   char H5Gcreate2var0[256];
	sprintf(H5Gcreate2var0, "7td9h");
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
   hid_t H5Gcreate2val1 = H5Gcreate2(H5Gcreate1val1, H5Gcreate2var0, 0, 0, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Gcreate2val1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
