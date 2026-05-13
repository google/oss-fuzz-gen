#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_47(char *fuzzData, size_t size)
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


   hbool_t H5allocate_memoryvar0;
	memset(&H5allocate_memoryvar0, 0, (sizeof H5allocate_memoryvar0));

   htri_t H5Fis_accessibleval1 = H5Fis_accessible(fuzzData, 0);
	if(0){
		fprintf(stderr, "err");
	}
	if(H5Fis_accessibleval1 < 0){
		fprintf(stderr, "err");
	}
   void* H5allocate_memoryval1 = H5allocate_memory(H5Fis_accessibleval1, H5allocate_memoryvar0);
	if(!H5allocate_memoryval1){
		fprintf(stderr, "err");
	}
   herr_t H5is_library_threadsafeval1 = H5is_library_threadsafe(&H5allocate_memoryvar0);
	if(H5is_library_threadsafeval1 < 0){
		fprintf(stderr, "err");
	}
   return 0;
}
