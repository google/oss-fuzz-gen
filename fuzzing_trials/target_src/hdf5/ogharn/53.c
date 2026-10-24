#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_53(char *fuzzData, size_t size)
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


   H5F_info2_t H5Fget_info2var0;
	memset(&H5Fget_info2var0, 0, (sizeof H5Fget_info2var0));

   hid_t H5Fopenval1 = H5Fopen(fuzzData, 1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   hid_t H5Gcreate_anonval1 = H5Gcreate_anon(H5Fopenval1, 0, 0);
	if(H5Gcreate_anonval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Fget_info2val1 = H5Fget_info2(H5Gcreate_anonval1, &H5Fget_info2var0);
	if(H5Fget_info2val1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
