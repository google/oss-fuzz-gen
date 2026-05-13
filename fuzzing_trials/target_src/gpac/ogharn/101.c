#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_101(char *fuzzData, size_t size)
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

   u8 gf_isom_create_piff_psec_boxvar0 = 1;
   u8 gf_isom_create_piff_psec_boxvar1 = 1;
   bin128 gf_isom_create_piff_psec_boxvar2;
	memset(&gf_isom_create_piff_psec_boxvar2, 0, (sizeof gf_isom_create_piff_psec_boxvar2));

   GF_ISOFile* gf_isom_open_fileval1 = gf_isom_open_file(fuzzData, GF_ISOM_OPEN_EDITVAL, NULL);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!gf_isom_open_fileval1){
		fprintf(stderr, "err");
		exit(0);	}
   GF_ISOSample* gf_isom_webvtt_to_sampleval1 = gf_isom_webvtt_to_sample((void*)gf_isom_open_fileval1);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!gf_isom_webvtt_to_sampleval1){
		fprintf(stderr, "err");
		exit(0);	}
   u32 gf_isom_linf_size_entryval1 = gf_isom_linf_size_entry((void*)gf_isom_open_fileval1);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(gf_isom_linf_size_entryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   GF_SampleEncryptionBox* gf_isom_create_piff_psec_boxval1 = gf_isom_create_piff_psec_box(gf_isom_create_piff_psec_boxvar0, gf_isom_linf_size_entryval1, 64, gf_isom_create_piff_psec_boxvar1, gf_isom_create_piff_psec_boxvar2);
	if(!gf_isom_create_piff_psec_boxval1){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
