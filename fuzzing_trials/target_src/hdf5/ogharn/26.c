#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

static herr_t H5I_free_tfp(void *obj, void **request){
exit(0);
}
int LLVMFuzzerTestOneInput_26(char *fuzzData, size_t size)
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


   H5G_info_t H5Gget_infovar0;
	memset(&H5Gget_infovar0, 0, (sizeof H5Gget_infovar0));

   hid_t H5Fopenval1 = H5Fopen(fuzzData, 1, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fopenval1 < 0){
		fprintf(stderr, "err");
	}
   herr_t H5Gget_infoval1 = H5Gget_info(H5Fopenval1, &H5Gget_infovar0);
	if(H5Gget_infoval1 < 0){
		fprintf(stderr, "err");
	}
   H5I_type_t H5Iregister_typeval1 = H5Iregister_type1(H5Gget_infoval1, 64, H5I_free_tfp);
	if(!H5Iregister_typeval1){
		fprintf(stderr, "err");
	}
   return 0;
}
