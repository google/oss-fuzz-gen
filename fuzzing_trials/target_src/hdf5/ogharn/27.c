#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_27(char *fuzzData, size_t size)
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
   herr_t H5Freset_mdc_hit_rate_statsval1 = H5Freset_mdc_hit_rate_stats(H5Fopenval1);
	if(H5Freset_mdc_hit_rate_statsval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
