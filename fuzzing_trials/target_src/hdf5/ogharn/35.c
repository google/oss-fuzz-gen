#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_35(char *fuzzData, size_t size)
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


   hbool_t H5Fget_mdc_logging_statusvar0;
	memset(&H5Fget_mdc_logging_statusvar0, 0, (sizeof H5Fget_mdc_logging_statusvar0));

   hbool_t H5Fget_mdc_logging_statusvar1;
	memset(&H5Fget_mdc_logging_statusvar1, 0, (sizeof H5Fget_mdc_logging_statusvar1));

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
   herr_t H5Fget_mdc_logging_statusval1 = H5Fget_mdc_logging_status(H5Fopenval1, &H5Fget_mdc_logging_statusvar0, &H5Fget_mdc_logging_statusvar1);
	if(H5Fget_mdc_logging_statusval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
