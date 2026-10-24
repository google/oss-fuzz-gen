#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_23(char *fuzzData, size_t size)
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


   H5F_retry_info_t H5Fget_metadata_read_retry_infovar0;
	memset(&H5Fget_metadata_read_retry_infovar0, 0, (sizeof H5Fget_metadata_read_retry_infovar0));

   hid_t H5Fopenval1 = H5Fopen(fuzzData, 64, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Fget_metadata_read_retry_infoval1 = H5Fget_metadata_read_retry_info(H5Fopenval1, &H5Fget_metadata_read_retry_infovar0);
	if(H5Fget_metadata_read_retry_infoval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
