#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_79(char *fuzzData, size_t size)
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

   GF_ISOOpenMode GF_ISOM_OPEN_EDITVAL = GF_ISOM_OPEN_EDIT;

   GF_ISOFile* gf_isom_open_fileval1 = gf_isom_open_file(fuzzData, GF_ISOM_OPEN_EDITVAL, NULL);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!gf_isom_open_fileval1){
		fprintf(stderr, "err");
		exit(0);	}
   GF_Box* gf_isom_create_meta_extensionsval1 = gf_isom_create_meta_extensions(gf_isom_open_fileval1, 64);
	if(!gf_isom_create_meta_extensionsval1){
		fprintf(stderr, "err");
		exit(0);	}
   u32 gf_isom_sample_get_subsample_entryval1 = gf_isom_sample_get_subsample_entry(gf_isom_open_fileval1, 1, -1, -1, NULL);
	if(gf_isom_sample_get_subsample_entryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   char* gf_cicp_color_transfer_nameval1 = gf_cicp_color_transfer_name(gf_isom_sample_get_subsample_entryval1);
	if(!gf_cicp_color_transfer_nameval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
