#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_57(char *fuzzData, size_t size)
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


   hid_t H5Fopenval1 = H5Fopen(fuzzData, 64, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   hid_t H5Iget_file_idval1 = H5Iget_file_id(H5Fopenval1);
	if(H5Iget_file_idval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Fcloseval1 = H5Fclose(H5Iget_file_idval1);
	if(H5Fcloseval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
