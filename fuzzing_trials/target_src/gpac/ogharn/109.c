#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_109(char *fuzzData, size_t size)
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
   GF_Box* gf_isom_clone_config_boxval1 = gf_isom_clone_config_box(gf_isom_create_meta_extensionsval1);
	if(!gf_isom_clone_config_boxval1){
		fprintf(stderr, "err");
		exit(0);	}
   gf_isom_check_position(NULL, gf_isom_clone_config_boxval1, 64);
   return 0;
}
