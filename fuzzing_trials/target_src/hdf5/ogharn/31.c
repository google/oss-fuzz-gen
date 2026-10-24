#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_31(char *fuzzData, size_t size)
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


   H5F_libver_t H5Fset_libver_boundsvar0;
	memset(&H5Fset_libver_boundsvar0, 0, (sizeof H5Fset_libver_boundsvar0));

   H5F_libver_t H5Fset_libver_boundsvar1;
	memset(&H5Fset_libver_boundsvar1, 0, (sizeof H5Fset_libver_boundsvar1));

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
   herr_t H5Fset_libver_boundsval1 = H5Fset_libver_bounds(H5Freopenval1, H5Fset_libver_boundsvar0, H5Fset_libver_boundsvar1);
	if(H5Fset_libver_boundsval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
