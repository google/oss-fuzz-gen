#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_19(char *fuzzData, size_t size)
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

   GF_MovieBox GetESDForTimevar0;
	memset(&GetESDForTimevar0, 0, (sizeof GetESDForTimevar0));

   GF_ISOTrackID GetESDForTimevar1;
	memset(&GetESDForTimevar1, 0, (sizeof GetESDForTimevar1));

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
   GF_Err GetESDForTimeval1 = GetESDForTime(&GetESDForTimevar0, GetESDForTimevar1, gf_isom_linf_size_entryval1, NULL);
   return 0;
}
