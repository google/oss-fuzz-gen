#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_29(char *fuzzData, size_t size)
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


   hbool_t H5Fset_dset_no_attrs_hintvar0;
	memset(&H5Fset_dset_no_attrs_hintvar0, 0, (sizeof H5Fset_dset_no_attrs_hintvar0));

   htri_t H5Fis_accessibleval1 = H5Fis_accessible(fuzzData, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fis_accessibleval1 < 0){
		fprintf(stderr, "err");
	}
   hid_t H5Fopenval1 = H5Fopen(fuzzData, H5Fis_accessibleval1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Fset_dset_no_attrs_hintval1 = H5Fset_dset_no_attrs_hint(H5Fopenval1, H5Fset_dset_no_attrs_hintvar0);
	if(H5Fset_dset_no_attrs_hintval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
