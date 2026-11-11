#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

static void H5_atclose_func_tfp(void *ctx){
exit(0);
}
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


   hsize_t H5Gget_objname_by_idxvar0;
	memset(&H5Gget_objname_by_idxvar0, 0, (sizeof H5Gget_objname_by_idxvar0));

   hid_t H5Fopenval1 = H5Fopen(fuzzData, 1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   ssize_t H5Gget_objname_by_idxval1 = H5Gget_objname_by_idx(H5Fopenval1, H5Gget_objname_by_idxvar0, fuzzData, strlen(fuzzData));
	if(0){
		fprintf(stderr, "err");
	}
	if(!H5Gget_objname_by_idxval1){
		fprintf(stderr, "err");
	}
   herr_t H5atcloseval1 = H5atclose(H5_atclose_func_tfp, (void*)fuzzData);
	if(H5atcloseval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
