#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpac/internal/isomedia_dev.h>
#include <gpac/constants.h>

int LLVMFuzzerTestOneInput_131(char *fuzzData, size_t size)
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

   GF_ISOOpenMode GF_ISOM_OPEN_READ_DUMPVAL = GF_ISOM_OPEN_READ_DUMP;
   u64 gf_audio_fmt_cicp_enumvaru64size = 256;

   GF_ISOFile* gf_isom_open_fileval1 = gf_isom_open_file(fuzzData, GF_ISOM_OPEN_READ_DUMPVAL, NULL);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(!gf_isom_open_fileval1){
		fprintf(stderr, "err");
		exit(0);	}
   u32 gf_isom_oinf_size_entryval1 = gf_isom_oinf_size_entry((void*)gf_isom_open_fileval1);
	if(0){
		fprintf(stderr, "err");
		exit(0);	}
	if(gf_isom_oinf_size_entryval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   u32 gf_audio_fmt_cicp_enumval1 = gf_audio_fmt_cicp_enum(gf_isom_oinf_size_entryval1, NULL, &gf_audio_fmt_cicp_enumvaru64size);
	if(gf_audio_fmt_cicp_enumval1 < 0){
		fprintf(stderr, "err");
		exit(0);	}
   return 0;
}
