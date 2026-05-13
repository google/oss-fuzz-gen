#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_14(char *fuzzData, size_t size)
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
   GF_ISOSample* gf_isom_webvtt_to_sampleval1 = gf_isom_webvtt_to_sample((void*)gf_isom_open_fileval1);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!gf_isom_webvtt_to_sampleval1){
		fprintf(stderr, "err");
		exit(0);	}
   GF_Err gf_isom_rewrite_text_sampleval1 = gf_isom_rewrite_text_sample(gf_isom_webvtt_to_sampleval1, -1, 64);
   gf_isom_set_last_error(NULL, gf_isom_rewrite_text_sampleval1);
   return 0;
}
